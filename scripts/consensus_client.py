#!/usr/bin/env python3
"""共识客户端 — chunked live-engine consensus enrichment of the units 表.

Nightly blocklist pipeline stage 2 (plan 2026-10-03-blocklist-pipeline-v1 T2):
select unpromoted units `WHERE verdict IS NULL ORDER BY rowid` in batches,
POST each batch to the engine's stream API, and write per-unit consensus
fields back (executemany, commit per chunk — the WHERE filter makes paging
advance monotonically). Memory redline: NDJSON responses are consumed LINE
BY LINE straight off the socket; the only Python-side accumulation is the
≤chunk update batch that executemany requires anyway. After every chunk the
process RSS is self-checked — 爆顶死任务不死机器.

Engine API contract (pinned against backend/main.py query_ips_stream →
_stream_lookup, 2026-10-03): POST {base}/api/query/stream, body
{"ips": [...]}, header x-ipradar-client: web (demo-mode guard; missing →
403 envelope). Response is NDJSON (`application/x-ndjson`), one JSON event
per line, discriminated by "type":
  {"type": "start", "total": N}
  {"type": "row", "idx": <input position>, "result": {lookup dict}}   # rows may be out of order
  {"type": "progress", "done": D, "total": N}                          # ignored
  {"type": "done", "invalid_lines": I, "ipv6_unsupported": V}          # terminal;
      on engine failure additionally {"error": msg, "code": code}
Non-2xx HTTP returns a JSON error envelope {"error": {code, message}}.
Every valid input yields exactly one row per idx (ipv6_unsupported is 恒 0).

Auth (final-review P1 fix, 2026-10-03): the engine's query endpoints carry
dependencies=[api_key_dep, require_ready] — programmatic (non-same-origin)
requests without a Bearer key get 401. Callers pass api_key=... → every
request (retries included) carries `Authorization: Bearer <api_key>`.

Pacing + rate-limit tolerance (same fix): the engine rate-limits keyed
requests at 60/min shared across the four query endpoints, so request
STARTS are paced ≥ MIN_REQUEST_INTERVAL_S apart, and HTTP 429 is treated
as TRANSIENT: sleep the error envelope's retry_after seconds (fallback
30s) and retry the SAME chunk. Rate-limit waits do NOT consume the retry
budget; a wedged limiter aborts loudly after _MAX_RATE_LIMIT_EVENTS
rate-limit events in one run.

Retry semantics (plan Global Constraints 「每块 3 次指数退避重试后仍失败 →
抛异常」): initial attempt + 3 retries = 4 attempts total, backoff 2/4/8s,
then raise. 4xx (except 429) is permanent — no retry. stats["requests"]
counts ALL HTTP attempts, stats["retries"] counts attempts beyond the
first (backoff and rate-limit waits alike), stats["rate_limited"] counts
429 responses seen.
"""
from __future__ import annotations

import http.client
import json
import resource
import sqlite3
import sys
import time
import urllib.error
import urllib.request

_STREAM_PATH = "/api/query/stream"
_HTTP_TIMEOUT_S = 60
# 3 次重试 → 共 4 次尝试(裁决 2026-10-03);测试注入 (0,0,0) 免真实等待
_BACKOFF_SECONDS = (2.0, 4.0, 8.0)
# 请求起点配速:引擎 keyed 桶 60/min(四查询端点共享)→ 1.1s 留裕量;
# 测试注入 0 保持套件快速。间隔按请求 START 计,非完成时刻。
MIN_REQUEST_INTERVAL_S = 1.1
_MAX_RATE_LIMIT_EVENTS = 10        # 单轮 429 容忍上限:楔死的限流器响亮中止
_RETRY_AFTER_FALLBACK_S = 30.0     # 429 信封缺 retry_after 时的兜底等待

_UPDATE_SQL = ("UPDATE units SET verdict=?, confidence=?, classes=?,"
               " sources=?, source_count=?, asn=?, country=? WHERE ip=?")


class MemoryBudgetExceeded(RuntimeError):
    """ru_maxrss 自检超过 --max-rss-mb 预算(每块处理后检查)。"""


class ConsensusStreamError(RuntimeError):
    """引擎 API 永久性失败:4xx 信封、done-error 事件、协议破损、缺行。
    5xx/网络错的重试耗尽后也以此终止(调方 catch → abort 整轮)。"""


def query_key(unit_ip: str) -> str:
    """单元 → 锚点查询键:CIDR 剥 /前缀(网络地址调 API),纯 IP 原样。

    产物行仍写单元原文(锚点二象性,Q3-A:共识取锚点,存储/出档取 CIDR)。
    """
    return unit_ip.partition("/")[0]


def _current_rss_mb() -> float:
    """ru_maxrss → MB(Linux 单位 KB,macOS 单位字节)。"""
    kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return kb / (1024 * 1024) if sys.platform == "darwin" else kb / 1024


def _merged_str(row: dict, field: str) -> str:
    """MergedField 胜者 str(value);字段或 value 缺失留空(裁决:缺失留空)。"""
    value = (row.get(field) or {}).get("value")
    return "" if value is None else str(value)


def _extract_fields(row: dict) -> tuple:
    """lookup result → (verdict, confidence, classes, sources, source_count,
    asn, country),按 Global Constraints 入选口径:

    - verdict = threat.verdict(全行存储,含 suspicious/benign/reserved);
    - 仅 malicious 行计数值字段:source_count/classes/sources 取「全部
      detected ∧ verdict=="malicious" 的 classification」里 distinct 源名
      与 type 并集;confidence = threat.confidence;
    - 非 malicious 行数值/列表字段 NULL(suspicious 不入选,仅留 verdict)。
    """
    threat = row.get("threat") or {}
    verdict = threat.get("verdict")
    if not verdict:
        # 无 verdict 行若落库 NULL 会永远留在 WHERE verdict IS NULL 集合里
        # → 分页死循环。协议破损,响亮失败。
        raise ConsensusStreamError(
            f"row {row.get('ip')!r}: missing threat.verdict")
    if verdict != "malicious":
        return (verdict, None, None, None, None, None, None)
    src_names: set[str] = set()
    classes: set[str] = set()
    for cls in (row.get("classifications") or {}).values():
        if cls.get("detected") and cls.get("verdict") == "malicious":
            if cls.get("type"):
                classes.add(cls["type"])
            src_names.update(
                s.get("source") for s in (cls.get("sources") or [])
                if s.get("source"))
    return (verdict, threat.get("confidence"),
            ";".join(sorted(classes)), ";".join(sorted(src_names)),
            len(src_names), _merged_str(row, "asn"), _merged_str(row, "country"))


def _stream_once(url: str, anchors: list[str], units: list[str],
                 user_agent: str, api_key: str | None = None) -> list[tuple]:
    """POST one chunk and stream-parse the NDJSON line by line → bounded
    UPDATE tuples (*fields, unit_ip). Raises ConsensusStreamError on
    done-error events, protocol breakage, or missing rows; 5xx/network
    errors propagate as URLError/OSError/HTTPException for the retry
    wrapper (IncompleteRead = torn chunked stream — the engine's
    StreamingResponse is transfer-chunked). api_key set → Bearer 头逐请求
    携带(含重试,引擎 api_key_dep 无 key 即 401)。"""
    headers = {"Content-Type": "application/json",
               "Accept": "application/x-ndjson",
               "x-ipradar-client": "web",       # demo 模式守卫(缺 → 403 信封)
               "User-Agent": user_agent}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(
        url,
        data=json.dumps({"ips": anchors}, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST")
    updates: list[tuple] = []
    seen: set[int] = set()
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
        for raw in resp:                          # 行迭代,绝不整体物化
            line = raw.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError as exc:    # 协议破损,响亮失败
                raise ConsensusStreamError(
                    f"malformed NDJSON line: {line[:120]!r}") from exc
            etype = evt.get("type")
            if etype == "row":
                idx = evt.get("idx")
                if not isinstance(idx, int) or not 0 <= idx < len(units):
                    raise ConsensusStreamError(
                        f"row idx {idx!r} out of range for chunk of"
                        f" {len(units)}")
                updates.append((*_extract_fields(evt.get("result") or {}),
                                units[idx]))
                seen.add(idx)
            elif etype == "done":
                if evt.get("error"):              # done-error 不静默
                    raise ConsensusStreamError(
                        f"engine stream error (code={evt.get('code')!r}):"
                        f" {evt['error']}")
                break                              # terminal event
            # start/progress/未知事件:忽略(start/progress 是协议心跳)
    missing = len(units) - len(seen)
    if missing:
        raise ConsensusStreamError(
            f"stream done but {missing}/{len(units)} rows missing"
            f" (inputs: {units})")
    return updates


def _envelope_detail(exc: urllib.error.HTTPError) -> str:
    """Best-effort: pull {"error": {code, message}} out of a 5xx body so the
    abort message (Task 4 的 error manifest) carries the engine's own words."""
    try:
        err = json.loads(exc.read().decode("utf-8")).get("error") or {}
        code, message = err.get("code"), err.get("message")
        if code or message:
            return f"{code}: {message}" if message else str(code)
    except Exception:
        pass                                       # 非 JSON body → 退回 reason
    return str(exc.reason)


def _retry_after_seconds(exc: urllib.error.HTTPError) -> float:
    """429 信封 {"error": {..., retry_after}} → 秒;缺失/破损时
    兜底 _RETRY_AFTER_FALLBACK_S(30s,夜间轮宁等勿弃)。"""
    try:
        err = json.loads(exc.read().decode("utf-8")).get("error") or {}
        retry_after = err.get("retry_after")
        if isinstance(retry_after, (int, float)) and retry_after > 0:
            return float(retry_after)
    except Exception:
        pass                                       # 非 JSON body → 兜底
    return _RETRY_AFTER_FALLBACK_S


class _RequestPacer:
    """请求起点配速:任意相邻两次请求 START 间隔 ≥ MIN_REQUEST_INTERVAL_S。

    引擎 keyed 桶 60/min(四查询端点共享)→ 1.1s 留裕量;时基 monotonic,
    sleep 后取当下时刻作新起点(是起点间隔,非完成间隔)。实例由
    enrich_with_consensus 创建并贯穿全轮(跨块、跨重试共用一个时轴)。"""

    def __init__(self) -> None:
        self._last_start: float | None = None

    def wait(self) -> None:
        if self._last_start is not None:
            remaining = MIN_REQUEST_INTERVAL_S - (
                time.monotonic() - self._last_start)
            if remaining > 0:
                time.sleep(remaining)
        self._last_start = time.monotonic()


def _fetch_chunk_with_retries(url: str, anchors: list[str], units: list[str],
                              user_agent: str, stats: dict,
                              api_key: str | None = None,
                              pacer: "_RequestPacer | None" = None) -> list[tuple]:
    """Same-chunk retry: 5xx / network / timeout → exponential backoff
    2/4/8s, 4 attempts total, then ConsensusStreamError (caller aborts).
    429 is TRANSIENT — sleep the envelope's retry_after and retry the same
    chunk WITHOUT consuming the attempt budget (wedged limiter aborts after
    _MAX_RATE_LIMIT_EVENTS events); every attempt starts through the pacer.
    4xx envelopes (401/403/...) are permanent — immediate raise."""
    attempt = 0
    failure: Exception | None = None
    failure_desc = ""
    while True:
        if pacer is not None:
            pacer.wait()                           # 请求起点配速(含重试)
        stats["requests"] += 1                    # 所有 HTTP 尝试都计数
        try:
            return _stream_once(url, anchors, units, user_agent, api_key)
        except ConsensusStreamError:
            raise                                  # 永久错不重试
        except urllib.error.HTTPError as exc:      # URLError 子类,先接
            if exc.code == 429:                    # 限流:瞬态,不耗重试预算
                stats["rate_limited"] += 1
                if stats["rate_limited"] > _MAX_RATE_LIMIT_EVENTS:
                    raise ConsensusStreamError(
                        f"rate-limited {stats['rate_limited']} times"
                        f" (>{_MAX_RATE_LIMIT_EVENTS}; wedged limiter?)"
                        " — aborting run") from exc
                time.sleep(_retry_after_seconds(exc))
                stats["retries"] += 1             # 首次之后的尝试(同口径)
                continue
            if exc.code < 500:
                raise ConsensusStreamError(
                    f"engine HTTP {exc.code}: {exc.reason}") from exc
            failure, failure_desc = exc, f"engine HTTP {exc.code}:" \
                f" {_envelope_detail(exc)}"
        except (urllib.error.URLError, OSError,
                http.client.HTTPException) as exc:
            failure = exc                          # 网络错/超时/断流(OSError 母集)
            failure_desc = f"network error: {exc}"
        if attempt >= len(_BACKOFF_SECONDS):       # 已重试 3 次(共 4 尝试)
            raise ConsensusStreamError(
                f"chunk failed after {attempt + 1} attempts: {failure_desc}"
            ) from failure
        time.sleep(_BACKOFF_SECONDS[attempt])
        attempt += 1
        stats["retries"] += 1


def enrich_with_consensus(db: sqlite3.Connection, api_base: str, *,
                          chunk: int = 2500, max_rss_mb: int = 140,
                          user_agent: str = "ipradar-blocklist-exporter/1.0",
                          api_key: str | None = None
                          ) -> dict:
    """Enrich units.verdict/confidence/classes/sources/source_count/asn/country
    from the live engine (caller has ALTERed the columns in).

    api_key: engine query endpoints require Bearer auth for programmatic
    (non-same-origin) requests — set this or every chunk 401s.

    Paging: `WHERE verdict IS NULL ORDER BY rowid LIMIT chunk` — committed
    chunks drop out of the filter, so the cursor advances monotonically and
    a rerun resumes from the first unprocessed unit. chunk 默认 2500(smoke
    宇宙 ~3.5M 单元 → ~1400 块 × 1.1s 配速 ≈ 26 min;内存仍有界:在飞
    ≤2500 行 ≈ 几 MB)。返回 stats:{"queried", "malicious", "requests",
    "retries", "rate_limited", "elapsed_s"}。
    """
    url = api_base.rstrip("/") + _STREAM_PATH
    stats: dict = {"queried": 0, "malicious": 0, "requests": 0,
                   "retries": 0, "rate_limited": 0}
    pacer = _RequestPacer()
    started = time.monotonic()
    while True:
        units = [r[0] for r in db.execute(
            "SELECT ip FROM units WHERE verdict IS NULL ORDER BY rowid"
            " LIMIT ?", (chunk,))]
        if not units:
            break
        updates = _fetch_chunk_with_retries(
            url, [query_key(u) for u in units], units, user_agent, stats,
            api_key=api_key, pacer=pacer)
        db.executemany(_UPDATE_SQL, updates)
        db.commit()                                # 块粒度提交:分页单调推进
        stats["queried"] += len(units)
        stats["malicious"] += sum(1 for u in updates if u[0] == "malicious")
        if _current_rss_mb() > max_rss_mb:
            raise MemoryBudgetExceeded(
                f"RSS {_current_rss_mb():.1f}MB exceeds budget"
                f" {max_rss_mb}MB")
    stats["elapsed_s"] = time.monotonic() - started
    return stats
