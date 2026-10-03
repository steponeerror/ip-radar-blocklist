"""Task 2 tests — consensus_client: chunked stream-API enrichment of units.

Stub strategy (Step 1-pinned engine protocol, backend/main.py query_ips_stream
→ _stream_lookup): stdlib ThreadingHTTPServer replays canned NDJSON events —
start{total} → row{idx,result}×N (out of input order on purpose) →
progress{done,total} → done{invalid_lines,ipv6_unsupported}; a failure done
carries error+code. Pure-stdlib module under test: no engine import here.

Retry semantics (supervisor ruling on plan text 「3 次指数退避重试」):
initial attempt + 3 retries = 4 attempts total, backoffs 2/4/8s; requests
stat counts ALL HTTP attempts, retries counts attempts beyond the first.

Auth/pacing/429 tolerance (final-review P1 fix): api_key → every request
(retries included) carries `Authorization: Bearer <key>` (engine api_key_dep
else 401); request starts are paced ≥ MIN_REQUEST_INTERVAL_S; HTTP 429 is
transient — sleep the envelope's retry_after, retry the same chunk without
consuming the attempt budget, abort loudly past 10 rate-limit events per run.

T7 (self-check metric): the per-chunk budget check measures ANONYMOUS RSS
(/proc/self/smaps_rollup `Anonymous:` line, kB → MB) — ru_maxrss total
conflates reclaimable mmap file pages (run #1: most of 169MB peak) with real
allocation and would false-abort under the server's 150m cgroup. Injection
seam = the `_SMAPS_ROLLUP_PATH` module constant (monkeypatched to a tmp
file). Any read/parse failure → warn ONCE on stderr, fall back to the old
ru_maxrss total. peak_rss_anon_mb = max of per-chunk samples (current
sampling, not a kernel peak — between-sample spikes are the cgroup's job).

T8 (server-trial finding, 2026-10-03): the 2-core 964Mi server engine
cannot sustain the default pace and drops into a transient warming state
(HTTP 503 {"error": {code: "warming"}}) — the generic 5xx backoff (14s
total) cannot outwait it. 503-warming sleeps 60s and retries the same
chunk budget-free, capped at 5 warming events per run (then loud abort);
ANY unreadable/non-JSON 503 body is also treated as warming (one-shot
nightly — safest interpretation). The pace itself is env-overridable via
IPRADAR_REQUEST_INTERVAL_S (pure-function parse seam, default 1.1, clamp
≥ 0.1; the server compose sets 2.2 ≈ 570 lookups/s).
"""
import json
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))   # scripts/ as namespace pkg portion

from scripts import consensus_client as cc  # noqa: E402

# 全列建表(caller 先 ALTER 的形态,测试按 Global Constraints 全列自建)
UNITS_DDL = """
CREATE TABLE units(
    ip TEXT PRIMARY KEY,
    is_v6 INTEGER NOT NULL,
    is_cidr INTEGER NOT NULL,
    last_seen TEXT,
    first_seen TEXT,
    verdict TEXT, confidence INTEGER, classes TEXT, sources TEXT,
    source_count INTEGER, asn TEXT, country TEXT
)
"""

NO_BACKOFF = (0.0, 0.0, 0.0)   # test injection: real 2/4/8s is nightly-grade


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    """配速常量归零保套件快(引擎 1.1s 真实配速是夜间轮量级);
    专测配速的用例在测试体内自行覆写回正值。"""
    monkeypatch.setattr(cc, "MIN_REQUEST_INTERVAL_S", 0.0)


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.execute(UNITS_DDL)
    return conn


def _add_units(conn: sqlite3.Connection, *ips: str):
    is_cidr = 1 if "/" in ips else 0
    conn.executemany(
        "INSERT INTO units(ip, is_v6, is_cidr) VALUES (?, 0, ?)",
        [(ip, 1 if "/" in ip else 0) for ip in ips])


# ── canned row builders: exact engine LookupResult.to_dict() shape ──

def _merge(value, confidence=90):
    return {"value": value, "confidence": confidence, "algorithm": "voting",
            "sources": [{"source": "geo", "value": value,
                         "reliability": 1.0, "authoritative": True}]}


def _cls(type_, verdict, detected, sources):
    return {"type": type_, "verdict": verdict, "detected": detected,
            "confidence": 80, "algorithm": "logodds", "corroborated": len(sources) >= 2,
            "reporter_total": len(sources), "verdict_conflict": False,
            "has_archive": False, "malware_names": [], "details": [],
            "sources": [{"source": s, "value": True, "reliability": 0.9,
                         "authoritative": False} for s in sources]}


def _row(ip, verdict, confidence, classifications=None,
         is_reserved=False, asn="64512", country="US"):
    return {"ip": ip, "country": _merge(country), "city": _merge(None),
            "city_zh": None, "location": None, "asn": _merge(asn),
            "as_name": _merge("TEST AS"), "ip_range": _merge(None),
            "is_isp": False,
            "threat": {"verdict": verdict, "confidence": confidence,
                       "types": [], "is_cdn": False},
            "classifications": classifications or {},
            "attributes": {}, "is_reserved": is_reserved}


# Step 1 钉死的 NDJSON 事件协议:事件序列封装
def _ndjson(*events) -> bytes:
    return ("".join(json.dumps(e) + "\n" for e in events)).encode("utf-8")


def _start(ips) -> dict:
    return {"type": "start", "total": len(ips)}


def _row_evt(idx, result) -> dict:
    return {"type": "row", "idx": idx, "result": result}


def _done_ok() -> dict:
    return {"type": "done", "invalid_lines": 0, "ipv6_unsupported": 0}


def _envelope(code, message) -> bytes:
    return json.dumps({"error": {"code": code, "message": message}}).encode("utf-8")


def _rl_envelope(retry_after) -> bytes:
    """引擎 429 信封(main.py _rate_limit_handler 钉死形态):
    {"error": {code, message, retry_after}}。"""
    return json.dumps({"error": {"code": "rate_limited",
                                 "message": "rate limit exceeded",
                                 "retry_after": retry_after}}).encode("utf-8")


def _benign_responder(attempt_no, ips, headers):
    """通用全 benign 回放:每输入恰一行,顺序直出。"""
    events = [_start(ips)]
    events += [_row_evt(i, _row(ip, "benign", 0)) for i, ip in enumerate(ips)]
    events.append(_done_ok())
    return 200, "application/x-ndjson", _ndjson(*events)


# ── stub server: records every request, replays canned protocol ──

class _Stub:
    """responder(attempt_no, ips, headers) -> (status, content_type, payload)."""

    def __init__(self, responder):
        self.log_headers: list[dict] = []
        self.log_bodies: list[list[str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                ips = json.loads(body).get("ips", [])
                outer.log_headers.append(
                    {k.lower(): v for k, v in self.headers.items()})
                outer.log_bodies.append(ips)
                status, ctype, payload = responder(
                    len(outer.log_bodies), ips, outer.log_headers[-1])
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # silence request logging
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def stub():
    s = None

    def factory(responder):
        nonlocal s
        s = _Stub(responder)
        return s

    yield factory
    if s is not None:
        s.stop()


# ── canned universe (main field-semantics test) ──

def _main_responder(attempt_no, ips, headers):
    """Full-protocol replay for the 4-unit universe, rows emitted OUT OF
    input order (idx 2,0,3,1) — mapping must go through idx, not position."""
    results = {
        "203.0.113.7": _row(
            "203.0.113.7", "malicious", 87,
            classifications={
                # 跨 classification 去重口径:两 detection 共享 dataplane
                "scanner": _cls("scanner", "malicious", True,
                                ["dataplane", "turris_greylist"]),
                "spam": _cls("spam", "malicious", True,
                             ["dataplane", "blocklistde"]),
                # suspicious detection:不进 source_count/classes
                "c2": _cls("c2", "suspicious", True, ["shodan"]),
                # archive 章:detected False,不计数
                "archive": _cls("archive", "malicious", False, ["misp_archive"]),
            }),
        "203.0.113.0": _row(
            "203.0.113.0", "malicious", 60,
            classifications={"scanner": _cls("scanner", "malicious", True,
                                             ["dataplane"])},
            asn=None, country="DE"),     # 缺失 MergedField value → ""
        "198.51.100.5": _row(
            "198.51.100.5", "suspicious", 40,
            classifications={"scanner": _cls("scanner", "malicious", True,
                                             ["dataplane"])}),
        "192.0.2.1": _row("192.0.2.1", "benign", 0, is_reserved=True),
    }
    order = [2, 0, 3, 1]
    events = [_start(ips)]
    for idx in order:
        events.append(_row_evt(idx, results[ips[idx]]))
    events.append({"type": "progress", "done": len(ips), "total": len(ips)})
    events.append(_done_ok())
    return 200, "application/x-ndjson", _ndjson(*events)


def _units_by_ip(conn):
    return {r[0]: r[1:] for r in conn.execute(
        "SELECT ip, verdict, confidence, classes, sources, source_count,"
        " asn, country FROM units")}


# ── tests ──

def test_query_key_strips_prefix_anchor_form():
    assert cc.query_key("203.0.113.0/24") == "203.0.113.0"
    assert cc.query_key("2001:db8:aaaa::/48") == "2001:db8:aaaa::"
    assert cc.query_key("1.2.3.4/32") == "1.2.3.4"
    assert cc.query_key("2001:db8::1") == "2001:db8::1"     # 无 / 原样
    assert cc.query_key("192.0.2.7") == "192.0.2.7"


def test_enrich_fields_headers_anchors_and_stats(db, stub):
    _add_units(db, "203.0.113.7", "203.0.113.0/24", "198.51.100.5", "192.0.2.1")
    s = stub(_main_responder)

    stats = cc.enrich_with_consensus(db, s.base)

    # demo-mode 守卫头 + UA 逐请求都在;无 key 时绝不带 Authorization
    for h in s.log_headers:
        assert h.get("x-ipradar-client") == "web"
        assert h.get("user-agent") == "ipradar-blocklist-exporter/1.0"
        assert h.get("content-type") == "application/json"
        assert "authorization" not in h
    # body ips 是锚点形态(CIDR 剥前缀),顺序 = rowid 序
    assert s.log_bodies == [["203.0.113.7", "203.0.113.0",
                             "198.51.100.5", "192.0.2.1"]]

    rows = _units_by_ip(db)
    # malicious:跨 classification 去重 source_count=3,classes 并集,threat.confidence
    assert rows["203.0.113.7"] == (
        "malicious", 87, "scanner;spam",
        "blocklistde;dataplane;turris_greylist", 3, "64512", "US")
    # CIDR 行:键仍是单元原文,字段来自锚点行;缺失 asn value → ""
    assert rows["203.0.113.0/24"] == (
        "malicious", 60, "scanner", "dataplane", 1, "", "DE")
    # suspicious:verdict 入库但不计数,数值/列表字段 NULL
    assert rows["198.51.100.5"] == ("suspicious", None, None, None,
                                    None, None, None)
    # reserved/clean:仅 verdict
    assert rows["192.0.2.1"] == ("benign", None, None, None,
                                 None, None, None)

    assert set(stats) == {"queried", "malicious", "requests", "retries",
                          "rate_limited", "warming_waits", "peak_rss_anon_mb",
                          "elapsed_s"}
    assert stats["queried"] == 4
    assert stats["malicious"] == 2
    assert stats["requests"] == 1
    assert stats["retries"] == 0
    assert stats["rate_limited"] == 0
    assert stats["warming_waits"] == 0
    assert stats["elapsed_s"] >= 0


def test_done_error_event_raises(db, stub):
    _add_units(db, "203.0.113.7")

    def responder(attempt_no, ips, headers):
        events = [_start(ips),
                  _row_evt(0, _row("203.0.113.7", "malicious", 87)),
                  {"type": "done", "invalid_lines": 0, "ipv6_unsupported": 0,
                   "error": "boom during lookup", "code": "internal"}]
        return 200, "application/x-ndjson", _ndjson(*events)

    s = stub(responder)
    with pytest.raises(cc.ConsensusStreamError, match="boom during lookup"):
        cc.enrich_with_consensus(db, s.base)
    # 中途 error → 该块不入库
    assert _units_by_ip(db)["203.0.113.7"][0] is None
    assert s.log_bodies[0] == ["203.0.113.7"]


def test_missing_rows_in_done_stream_raises(db, stub):
    """Engine skips an input (no row for its idx) → loud failure, never a
    silent partial chunk nor a WHERE-verdict-IS-NULL infinite loop."""
    _add_units(db, "203.0.113.7", "198.51.100.5")

    def responder(attempt_no, ips, headers):
        return 200, "application/x-ndjson", _ndjson(
            _start(ips), _row_evt(0, _row("203.0.113.7", "benign", 0)),
            _done_ok())                       # idx 1 never emitted

    s = stub(responder)
    with pytest.raises(cc.ConsensusStreamError, match="missing"):
        cc.enrich_with_consensus(db, s.base)
    assert _units_by_ip(db)["203.0.113.7"][0] is None


def test_http_500_then_200_retries_same_chunk(db, stub, monkeypatch):
    monkeypatch.setattr(cc, "_BACKOFF_SECONDS", NO_BACKOFF)
    _add_units(db, "203.0.113.7")

    def responder(attempt_no, ips, headers):
        if attempt_no == 1:
            return 500, "application/json", _envelope("internal", "overloaded")
        events = [_start(ips),
                  _row_evt(0, _row("203.0.113.7", "malicious", 87,
                                   classifications={
                                       "scanner": _cls("scanner", "malicious",
                                                       True, ["dataplane"])})),
                  _done_ok()]
        return 200, "application/x-ndjson", _ndjson(*events)

    s = stub(responder)
    stats = cc.enrich_with_consensus(db, s.base)
    assert stats["requests"] == 2      # all attempts count
    assert stats["retries"] == 1       # attempts beyond the first
    assert stats["queried"] == 1       # unit counted once despite retry
    assert _units_by_ip(db)["203.0.113.7"] == (
        "malicious", 87, "scanner", "dataplane", 1, "64512", "US")


def test_mid_stream_chunked_tear_retries_then_succeeds(db, monkeypatch):
    """Torn chunked transfer (engine streams via Transfer-Encoding: chunked):
    server claims a 5-byte chunk but closes after 2 → client IncompleteRead
    (HTTPException, not OSError) → must be retried like any network error.
    Standalone raw handler — the canned stub always speaks the full protocol."""
    monkeypatch.setattr(cc, "_BACKOFF_SECONDS", NO_BACKOFF)
    _add_units(db, "203.0.113.7")
    attempts = {"n": 0}

    class TearHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"      # chunked 无 Content-Length 的前提

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            attempts["n"] += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            if attempts["n"] == 1:         # 撕裂流:块声明 5 字节只给 2
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                start = _ndjson(_start(["203.0.113.7"]))
                self.wfile.write(f"{len(start):x}\r\n".encode()
                                 + start + b"\r\n")
                self.wfile.write(b"5\r\nab")   # 谎报后断连
                self.close_connection = True
                return
            payload = _ndjson(
                _start(["203.0.113.7"]),
                _row_evt(0, _row("203.0.113.7", "malicious", 87,
                                 classifications={"scanner": _cls(
                                     "scanner", "malicious", True,
                                     ["dataplane"])})),
                _done_ok())
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), TearHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        stats = cc.enrich_with_consensus(
            db, f"http://127.0.0.1:{server.server_address[1]}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert stats["requests"] == 2
    assert stats["retries"] == 1
    assert _units_by_ip(db)["203.0.113.7"] == (
        "malicious", 87, "scanner", "dataplane", 1, "64512", "US")


def test_retry_exhausted_after_4_attempts_raises(db, stub, monkeypatch):
    """Ruling: initial + 3 retries = 4 attempts total (backoffs 2/4/8s),
    then raise — caller aborts the run."""
    monkeypatch.setattr(cc, "_BACKOFF_SECONDS", NO_BACKOFF)
    _add_units(db, "203.0.113.7")
    s = stub(lambda n, ips, h: (500, "application/json",
                                _envelope("internal", "down")))

    with pytest.raises(cc.ConsensusStreamError, match="down"):
        cc.enrich_with_consensus(db, s.base)
    assert len(s.log_bodies) == 4
    assert _units_by_ip(db)["203.0.113.7"][0] is None   # nothing stored


def test_http_4xx_raises_immediately_without_retry(db, stub):
    _add_units(db, "203.0.113.7")
    s = stub(lambda n, ips, h: (403, "application/json",
                                _envelope("forbidden", "Forbidden")))

    with pytest.raises(cc.ConsensusStreamError, match="403"):
        cc.enrich_with_consensus(db, s.base)
    assert len(s.log_bodies) == 1       # 4xx 是永久错,不重试


# ── T7:匿名 RSS 自检(smaps_rollup Anonymous;路径常量即注入接缝)──

def _smaps_inject(monkeypatch, tmp_path, anon_kb):
    """伪 /proc/self/smaps_rollup:Anonymous 值自由设定(kB)。"""
    p = tmp_path / "smaps_rollup"
    p.write_text(f"Rss: {anon_kb + 4096} kB\n"
                 f"Anonymous: {anon_kb} kB\n", encoding="ascii")
    monkeypatch.setattr(cc, "_SMAPS_ROLLUP_PATH", str(p))
    return p


def test_memory_budget_exceeded_after_chunk(db, stub, monkeypatch, tmp_path):
    _smaps_inject(monkeypatch, tmp_path, 1022976)       # 999 MB 匿名
    _add_units(db, "203.0.113.7", "198.51.100.5", "192.0.2.1", "2001:db8::1")

    def responder(attempt_no, ips, headers):
        events = [_start(ips)]
        events += [_row_evt(i, _row(ip, "benign", 0))
                   for i, ip in enumerate(ips)]
        events.append(_done_ok())
        return 200, "application/x-ndjson", _ndjson(*events)

    s = stub(responder)
    with pytest.raises(cc.MemoryBudgetExceeded, match="anon.*140"):
        cc.enrich_with_consensus(db, s.base, chunk=2, max_rss_mb=140)
    # 第一块已提交,第二块未发 —— 爆顶即停,不多发一个请求
    rows = _units_by_ip(db)
    assert rows["203.0.113.7"][0] == "benign"
    assert rows["198.51.100.5"][0] == "benign"
    assert rows["192.0.2.1"][0] is None
    assert len(s.log_bodies) == 1


def test_current_anon_rss_mb_parses_anonymous_line(monkeypatch, tmp_path):
    _smaps_inject(monkeypatch, tmp_path, 20480)         # 20 MB
    assert cc._current_anon_rss_mb() == 20.0


def test_current_anon_rss_mb_parse_failure_falls_back_warns_once(
        monkeypatch, tmp_path, capsys):
    """任何读取/解析失败(缺文件/缺 Anonymous 行/值非整数)→ 三者都回退
    ru_maxrss 口径,stderr 恰好告警一次(单进程只喊一嗓子),不抛异常。"""
    monkeypatch.setattr(cc, "_current_rss_mb", lambda: 123.0)
    monkeypatch.setattr(cc, "_anon_rss_fallback_warned", False)
    missing = tmp_path / "nope"                          # 文件不存在
    no_line = tmp_path / "no_anon_line"                  # 缺 Anonymous 行
    no_line.write_text("Rss: 100 kB\n", encoding="ascii")
    bad_value = tmp_path / "non_integer"                 # 值非整数
    bad_value.write_text("Anonymous: abc kB\n", encoding="ascii")
    for path in (missing, no_line, bad_value):
        monkeypatch.setattr(cc, "_SMAPS_ROLLUP_PATH", str(path))
        assert cc._current_anon_rss_mb() == 123.0        # 全部回退,不抛
    assert capsys.readouterr().err.count("WARNING") == 1


def test_under_threshold_anon_passes_and_peak_recorded(db, stub, monkeypatch,
                                                       tmp_path):
    _smaps_inject(monkeypatch, tmp_path, 51200)          # 50 MB < 140
    _add_units(db, "203.0.113.7")

    s = stub(_benign_responder)
    stats = cc.enrich_with_consensus(db, s.base, max_rss_mb=140)

    assert stats["peak_rss_anon_mb"] == 50.0
    assert _units_by_ip(db)["203.0.113.7"][0] == "benign"


def test_peak_rss_anon_mb_tracks_max_sample(db, stub, monkeypatch, tmp_path):
    """峰值 = 各块采样的 max(当前采样,非内核维护峰值)。responder 在
    服务端逐请求改写伪 smaps,块后自检读到的采样值随之变化。"""
    p = _smaps_inject(monkeypatch, tmp_path, 10240)      # 初始 10 MB
    samples_kb = (10240, 30720, 20480)                   # 10 → 30 → 20 MB
    _add_units(db, "203.0.113.7", "198.51.100.5", "192.0.2.1")

    def responder(attempt_no, ips, headers):
        p.write_text(f"Anonymous: {samples_kb[attempt_no - 1]} kB\n",
                     encoding="ascii")
        return _benign_responder(attempt_no, ips, headers)

    s = stub(responder)
    stats = cc.enrich_with_consensus(db, s.base, chunk=1, max_rss_mb=140)

    assert [len(b) for b in s.log_bodies] == [1, 1, 1]   # 三块各一请求
    assert stats["peak_rss_anon_mb"] == 30.0             # 取采样最大值


def test_enrich_unreadable_smaps_falls_back_to_ru_maxrss(
        db, stub, monkeypatch, tmp_path, capsys):
    """整轮跑在不可读 smaps 上:逐块回退 ru_maxrss 值且只告警一次,
    不抛异常 —— 指标口径降级响亮,红线本身照常运转。"""
    monkeypatch.setattr(cc, "_SMAPS_ROLLUP_PATH", str(tmp_path / "nope"))
    monkeypatch.setattr(cc, "_current_rss_mb", lambda: 123.0)
    monkeypatch.setattr(cc, "_anon_rss_fallback_warned", False)
    _add_units(db, "203.0.113.7", "198.51.100.5")

    s = stub(_benign_responder)
    stats = cc.enrich_with_consensus(db, s.base, chunk=1, max_rss_mb=140)

    assert stats["peak_rss_anon_mb"] == 123.0            # 回退值参与峰值
    assert capsys.readouterr().err.count("WARNING") == 1  # 两块只喊一次


def test_chunked_pagination_and_v6_units(db, stub):
    ips = ["203.0.113.7", "198.51.100.5", "192.0.2.1", "2001:db8::1",
           "203.0.113.0/24"]
    _add_units(db, *ips)

    def responder(attempt_no, ips_in, headers):
        events = [_start(ips_in)]
        events += [_row_evt(i, _row(ip, "benign", 0))
                   for i, ip in enumerate(ips_in)]
        events.append(_done_ok())
        return 200, "application/x-ndjson", _ndjson(*events)

    s = stub(responder)
    stats = cc.enrich_with_consensus(db, s.base, chunk=2)

    assert [len(b) for b in s.log_bodies] == [2, 2, 1]
    assert s.log_bodies[2] == ["203.0.113.0"]      # 锚点形态直到最后一块
    assert stats["queried"] == 5
    assert stats["requests"] == 3
    # 全部入库(WHERE verdict IS NULL 分页推进到空)
    assert all(r[0] == "benign" for r in _units_by_ip(db).values())


def test_empty_universe_makes_no_requests(db, stub):
    s = stub(_main_responder)
    stats = cc.enrich_with_consensus(db, s.base)
    assert stats == {"queried": 0, "malicious": 0, "requests": 0,
                     "retries": 0, "rate_limited": 0, "warming_waits": 0,
                     "peak_rss_anon_mb": 0.0,
                     "elapsed_s": stats["elapsed_s"]}
    assert s.log_bodies == []


# ── final-review P1:Bearer 鉴权 / 配速 / 429 容忍 ──

def test_api_key_bearer_header_on_every_request_including_retries(
        db, stub, monkeypatch):
    """api_key 传入 → 每次请求(含重试)都带 Authorization: Bearer <key>。
    引擎 api_key_dep 对非同源程序化请求无 key 即 401,头必须在重试路径
    也存在(重试用同一 _stream_once 入口,非绕行)。"""
    monkeypatch.setattr(cc, "_BACKOFF_SECONDS", NO_BACKOFF)
    _add_units(db, "203.0.113.7")

    def responder(attempt_no, ips, headers):
        if attempt_no == 1:                     # 逼出一次重试
            return 503, "application/json", _envelope("unavailable", "blip")
        return 200, "application/x-ndjson", _ndjson(
            _start(ips), _row_evt(0, _row("203.0.113.7", "benign", 0)),
            _done_ok())

    s = stub(responder)
    cc.enrich_with_consensus(db, s.base, api_key="test-engine-key-1")
    assert len(s.log_headers) == 2              # 首次 + 重试都带 key
    for h in s.log_headers:
        assert h.get("authorization") == "Bearer test-engine-key-1"


def test_http_429_waits_retry_after_then_retries_same_chunk(
        db, stub, monkeypatch):
    """429 是瞬态非永久:按信封 retry_after 等待后重试同块,不耗 3 次
    预算,统计进 rate_limited —— 不同于其它 4xx 的立即中止。"""
    sleeps: list[float] = []
    monkeypatch.setattr(cc.time, "sleep", sleeps.append)
    _add_units(db, "203.0.113.7")

    def responder(attempt_no, ips, headers):
        if attempt_no == 1:
            return 429, "application/json", _rl_envelope(7)
        return 200, "application/x-ndjson", _ndjson(
            _start(ips), _row_evt(0, _row("203.0.113.7", "malicious", 87,
                                         classifications={"scanner": _cls(
                                             "scanner", "malicious", True,
                                             ["dataplane"])})),
            _done_ok())

    s = stub(responder)
    stats = cc.enrich_with_consensus(db, s.base)
    assert sleeps == [7.0]                      # retry_after 被尊重
    assert stats["rate_limited"] == 1
    assert stats["requests"] == 2               # 同块重试
    assert stats["retries"] == 1                # 首次之后的尝试
    assert stats["queried"] == 1                # 未计永久失败
    assert _units_by_ip(db)["203.0.113.7"][0] == "malicious"


def test_pacing_sleeps_remainder_between_request_starts(db, stub, monkeypatch):
    """请求起点配速(非完成时刻):MIN_REQUEST_INTERVAL_S > 0 时,第二个
    块的首请求前补足与上一请求起点的间隔余量;首请求无前驱不睡。"""
    monkeypatch.setattr(cc, "MIN_REQUEST_INTERVAL_S", 0.5)
    sleeps: list[float] = []
    monkeypatch.setattr(cc.time, "sleep", sleeps.append)
    _add_units(db, "203.0.113.7", "198.51.100.5")

    s = stub(_benign_responder)
    cc.enrich_with_consensus(db, s.base, chunk=1)

    assert [len(b) for b in s.log_bodies] == [1, 1]   # 两块,各一请求
    # 全部 200 无重试 → 唯一的 sleep 就是第二块前的配速余量;
    # sleep 被替换不耗时,余量 = 间隔 - 两次起点间真实耗时(本地环回
    # ≈ 毫秒级,断言窗口留足裕量)
    assert len(sleeps) == 1
    assert 0.3 <= sleeps[0] <= 0.5


def test_rate_limit_events_over_cap_abort_loudly(db, stub, monkeypatch):
    """楔死的限流器:单轮容忍 10 次 429,第 11 次响亮终止(而非无限等)。"""
    monkeypatch.setattr(cc.time, "sleep", lambda sec: None)
    _add_units(db, "203.0.113.7")
    s = stub(lambda n, ips, h: (429, "application/json", _rl_envelope(1)))

    with pytest.raises(cc.ConsensusStreamError, match="rate-limited"):
        cc.enrich_with_consensus(db, s.base)
    assert len(s.log_bodies) == 11              # 10 次容忍 + 1 次触发中止


# ── server-trial fix(T8):503 warming 容忍 + 配速 env 覆写 ──

def test_http_503_warming_waits_60s_retries_same_chunk(db, stub, monkeypatch):
    """引擎 503 warming(require_ready:X-IPRadar-Reason 头 → 信封 code=
    "warming")是瞬态:等 60s 后重试同块,不耗 3 次退避预算,统计进
    warming_waits —— 服务器试跑教训(2 核 964Mi 机被默认配速压进 warming
    态,通用 5xx 退避 2/4/8s 共 14s 不够耐心)。"""
    sleeps: list[float] = []                     # 60s 真睡是夜间轮量级
    monkeypatch.setattr(cc.time, "sleep", sleeps.append)
    _add_units(db, "203.0.113.7")

    def responder(attempt_no, ips, headers):
        if attempt_no == 1:
            return 503, "application/json", _envelope(
                "warming", "database is warming up")
        return 200, "application/x-ndjson", _ndjson(
            _start(ips), _row_evt(0, _row("203.0.113.7", "malicious", 87,
                                         classifications={"scanner": _cls(
                                             "scanner", "malicious", True,
                                             ["dataplane"])})),
            _done_ok())

    s = stub(responder)
    stats = cc.enrich_with_consensus(db, s.base)

    assert sleeps == [60.0]                      # 固定 60s warming 等待
    assert s.log_bodies == [["203.0.113.7"], ["203.0.113.7"]]  # 同块重试
    assert stats["warming_waits"] == 1
    assert stats["requests"] == 2                # 同块重试也计请求数
    assert stats["retries"] == 1                 # 首次之后的尝试(同口径)
    assert stats["rate_limited"] == 0            # 与 429 计数互不混入
    assert stats["queried"] == 1                 # 未计永久失败
    assert _units_by_ip(db)["203.0.113.7"][0] == "malicious"


def test_http_503_unreadable_body_treated_as_warming(db, stub, monkeypatch):
    """正文不可读/非 JSON 的 503 也按 warming 处理:一次性夜间轮,把任何
    503 当 warming 等待是最安全的解释(宁等勿弃,不误走 14s 预算耗尽)。"""
    sleeps: list[float] = []
    monkeypatch.setattr(cc.time, "sleep", sleeps.append)
    _add_units(db, "203.0.113.7")

    def responder(attempt_no, ips, headers):
        if attempt_no == 1:
            return 503, "text/plain", b"<html>gateway melted</html>"
        return 200, "application/x-ndjson", _ndjson(
            _start(ips), _row_evt(0, _row("203.0.113.7", "benign", 0)),
            _done_ok())

    s = stub(responder)
    stats = cc.enrich_with_consensus(db, s.base)

    assert sleeps == [60.0]
    assert stats["warming_waits"] == 1
    assert _units_by_ip(db)["203.0.113.7"][0] == "benign"


def test_warming_events_over_cap_abort_loudly(db, stub, monkeypatch):
    """引擎永不离开 warming:单轮容忍 5 次 warming 等待(5 × 60s),第 6
    次响亮终止(而非无限等);warming 不耗退避预算,靠事件计数封顶。"""
    monkeypatch.setattr(cc.time, "sleep", lambda sec: None)
    _add_units(db, "203.0.113.7")
    s = stub(lambda n, ips, h: (503, "application/json",
                                _envelope("warming",
                                          "database is warming up")))

    with pytest.raises(cc.ConsensusStreamError, match="warming 6 times"):
        cc.enrich_with_consensus(db, s.base)
    assert len(s.log_bodies) == 6                # 5 次容忍 + 1 次触发中止


def test_request_interval_env_override_parse():
    """配速 env 解析接缝(纯函数,免 reimport):IPRADAR_REQUEST_INTERVAL_S
    合法 "2.2" → 2.2;非法/缺失/空 → 默认 1.1;"0.01"/负值 → clamp 0.1。"""
    assert cc._request_interval_from_env("2.2") == 2.2
    assert cc._request_interval_from_env("abc") == 1.1
    assert cc._request_interval_from_env("") == 1.1
    assert cc._request_interval_from_env(None) == 1.1
    assert cc._request_interval_from_env("0.01") == 0.1
    assert cc._request_interval_from_env("-5") == 0.1
