#!/usr/bin/env python3
"""CLI 编排器 — nightly 黑名单导出全管线:scan → geo → emit → manifest.

#444 改版(规格 docs/research/2026-11-24-blocklist-scan-export-spec.md §5):
管线不再逐 IP 调引擎查询接口,改用引擎的按键序扫描器整库读一遍:

    python scripts/generate_blocklist.py \
        --engine-path <backend> --data-dir <LMDB data> \
        [--out-dir .] [--max-rss-mb 140] [--asof <epoch 秒>]

- scan:scripts/scan_units.py 调引擎 open_unit_scanner(引擎镜像必须含
  #444),把每个单元一行写进 sqlite(判定五列由扫描结果算;asn/country
  留 NULL);每批提交后量一次匿名内存,超 --max-rss-mb 即停。
- geo:按 emit 同一份排序键链选出进榜的全部单 IP(嵌套档位取最大档位
  条数),按 IP 数值排序;扫描句柄关闭之后 load_db()(先设
  IP_RADAR_POOL_CHILD=1,防它清理旧纪元目录 —— 数据卷只读挂载),逐个
  lookup() 补 asn/country 回写,并用同一份 extract_fields 把判定五列和
  扫描入库值逐列比:任何一个 IP 任何一列不同就停(前 10 个例子),
  GeoMismatchError → error manifest → 退出 1。
- emit:emit_tiers 原样(选档规则、文件格式不动)。
- manifest:清单加 asof(开跑时刻钉死)、epochs(各库纪元号)、scan_stats、
  geo_stats、stage_elapsed_s(各阶段耗时);elapsed_s、peak_rss_mb、
  peak_rss_anon_mb 照旧。

Work db 仍在 ``<out_dir>/.staging/work.db``(管线的唯一中间态;中止轮次
的陈旧副本启动时先删)。Manifest contract(T3 ledger ruling):emit_tiers
成功清单无 ctx 透传 —— 编排器把额外上下文合进返回的 dict 并在原子发布后
重写 manifest.json 本身。

Failure contract:ANY 异常 → write_error_manifest(只碰 manifest.json;
上一轮的档位文件原样保留),错误清单打到 stderr,退出 1。成功 → manifest
JSON 走 stdout(机器可读,cron/CI 直吃),每阶段一行带计数的进度走
stderr — stdout 永远只有 manifest。
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

# bootstrap: make `scripts` importable whether run as a file or via -m
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts import emit_tiers, scan_units  # noqa: E402

DEFAULT_ENGINE_PATH = Path("/home/huxiao/dev/pi-ip-lookup-tool/backend")

# T1 契约:调方建表;T2 契约:调方 ALTER 共识列
UNITS_DDL = """
CREATE TABLE units(
    ip TEXT PRIMARY KEY,
    is_v6 INTEGER NOT NULL,
    is_cidr INTEGER NOT NULL,
    last_seen TEXT,
    first_seen TEXT
)
"""
CONSENSUS_COLUMNS = ("verdict TEXT", "confidence INTEGER", "classes TEXT",
                     "sources TEXT", "source_count INTEGER", "asn TEXT",
                     "country TEXT")

# geo 阶段五列核对的不一致例子上限(错误信息里带前 10 个例子)
_MISMATCH_EXAMPLES = 10


class GeoMismatchError(RuntimeError):
    """geo 阶段判定核对失败。失败清单里带上这些值(原 #444 评审 P3-7;
    后四项 2026-11-25 加):looked_up = 停下之前查过的 IP 数;examples =
    不一致的例子(最多 _MISMATCH_EXAMPLES 条,每条带两边的值);verified =
    其中逐列核对过的 IP 数(其余是被跳过的和这些不一致的);
    peak_rss_anon_mb = 这一段到停下时的匿名内存峰值;changed_sources =
    扫描之后纪元变了的源;drift_skipped / drift_examples = 因为证据涉及
    这些源而只核对了一部分(或没核对)的地址数和例子。"""

    def __init__(self, message: str, *, looked_up: int,
                 examples: list[str], verified: int = 0,
                 peak_rss_anon_mb: float = 0.0,
                 changed_sources: list[str] | None = None,
                 drift_skipped: int = 0,
                 drift_examples: list[str] | None = None):
        super().__init__(message)
        self.looked_up = looked_up
        self.examples = list(examples)
        self.verified = verified
        self.peak_rss_anon_mb = peak_rss_anon_mb
        self.changed_sources = list(changed_sources or [])
        self.drift_skipped = drift_skipped
        self.drift_examples = list(drift_examples or [])


def _names(text: str | None) -> set[str]:
    """分号连接的源名/分类名串 → 集合(空串、NULL → 空集)。"""
    return set(text.split(";")) - {""} if text else set()


def _short(value, limit: int = 200) -> str:
    """例子里的值:repr 之后截到 limit 个字符(清单里一行别太长)。"""
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _sources_changed_since_scan(epochs: dict, sources) -> set[str]:
    """扫描开跑之后被重建过的源名集合。

    epochs = 扫描时钉住的各库纪元号(清单 scan_stats.epochs,来自扫描器
    open_unit_scanner);现在的纪元号读 ptr 文件。两边不同 = 这个源在扫描
    开跑之后换过纪元,或者已经不在启用名单里 —— 下文统称「被重建过的
    源」。epochs 为空(调用方没给)→ 空集,核对保持逐列严格。"""
    from ipdb._sources._lmdb import read_ptr
    by_name = {s.name: s for s in sources}
    changed: set[str] = set()
    for name, pinned in epochs.items():
        src = by_name.get(name)
        now = ([None, None] if src is None else
               [read_ptr(src._lmdb_base), read_ptr(src._lmdb6_base)])
        if now != list(pinned):
            changed.add(name)
    return changed


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Nightly ip-radar blocklist export: scan engine LMDB "
                    "shards in key order → fill asn/country for tier IPs "
                    "in-process → emit nested top_N tiers + manifest "
                    "(atomic publish).")
    p.add_argument("--engine-path", type=Path, default=DEFAULT_ENGINE_PATH,
                   help=f"ip-radar backend repo path (default: "
                        f"{DEFAULT_ENGINE_PATH}); imported read-only; the "
                        f"engine must contain #444 (ipdb._scan)")
    p.add_argument("--data-dir", type=Path, required=True,
                   help="engine LMDB data dir (IP_RADAR_DATA_DIR)")
    p.add_argument("--asof", type=float, default=None,
                   help="verdict time anchor in epoch seconds (default: "
                        "now at startup); pinned once, used by the scan "
                        "fusion AND the geo lookups, written to the "
                        "manifest")
    p.add_argument("--out-dir", type=Path, default=_REPO_ROOT,
                   help="artifact directory (default: repo root)")
    p.add_argument("--max-rss-mb", type=int, default=140,
                   help="anonymous-RSS budget in MB for the scan stage "
                        "(smaps_rollup `Anonymous:` line; unreadable -> "
                        "ru_maxrss total fallback with a warning); "
                        "exceeding aborts the run (default: 140)")
    return p.parse_args(argv)


def _log(msg: str) -> None:
    """进度只走 stderr —— stdout 是 manifest JSON 的专用通道。"""
    print(msg, file=sys.stderr, flush=True)


def _unlink_work_db(staging: Path) -> None:
    """Remove work.db (+ journal/wal siblings): stale copies from aborted
    runs at startup, our own copy on cleanup — the universe must not linger
    in .staging (gitignored either way)."""
    for leftover in staging.glob("work.db*"):
        try:
            leftover.unlink()
        except OSError:
            pass


def _close_staging(staging: Path) -> None:
    """Final .staging cleanup once our files are all gone (emit_tiers already
    moved its own out); others' content stays, so rmdir only if empty."""
    try:
        staging.rmdir()
    except OSError:
        pass


def _unlink_manifest_tmp(out_dir: Path) -> None:
    """Remove a stale manifest.json.tmp left by a run killed between the tmp
    write and the os.replace — out_dir must only ever show manifest.json
    (+ tier files) to consumers (mirrors stale work.db startup cleanup)."""
    try:
        (out_dir / "manifest.json.tmp").unlink()
    except OSError:
        pass


def _ip_sort_key(ip: str) -> tuple:
    """IP 数值排序键(v4 全部在前、v6 在后;族内按数值)。"""
    addr = ipaddress.ip_address(ip)
    return (addr.version, int(addr))


def _geo_fill_and_verify(db: sqlite3.Connection, *, asof: float,
                         max_rss_mb: int = 140,
                         epochs: dict | None = None) -> dict:
    """geo 阶段(#444):给进榜单 IP 补 asn/country,并核判定五列一致。

    进榜集合 = 档位会切的全部单 IP:嵌套档位取最大档位条数,排序键与
    emit_tiers 的档位 SQL 共用同一份常量(TIER_ORDER_BY,不抄两份 ——
    两处排序漂移 = 补查集合和档位集合不一致)。集合按 IP 数值重排后逐个
    lookup(调方保证扫描句柄已关;这里先设 IP_RADAR_POOL_CHILD=1 再
    load_db,防它清理旧纪元目录 —— 数据卷只读挂载)。

    每个 IP:lookup 结果的 asn/country 回写 units;判定五列(verdict、
    confidence、classes、sources、source_count)用同一份 extract_fields
    从 lookup 结果算出,与扫描入库值逐列比 —— 任何一个 IP 任何一列不同
    都停:GeoMismatchError(前 10 个例子),调方走 error manifest 路径。
    这一段自己也量匿名内存(load_db() 之后、补查途中每 500 个采一次),
    超过 max_rss_mb 同样停:容器的内存上限盖整轮,扫描阶段的读数代表不了
    这一段(#444 评审 P2-3)。

    扫描期间源被重建(#444 生产试跑 2026-11-25):扫描读的是开跑时钉住
    的纪元,这里 lookup() 读的是现在的纪元。生产上扫描要跑一个多小时,
    引擎照常重建源,所以两边读到的不是同一份数据的情况每轮都可能有。
    对不上的地址分两种:
      - 证据(入库的 sources ∪ 查询接口的 sources)里有被重建过的源:
        把被重建的源从两边去掉再核对没重建的那部分。按观测比,不按五列
        比 —— 入库 sources 里有和指控者同组的证人(例如基础设施地址的
        良性断言),指控者被去掉后组就不算恶意组,证人也就不在查询接口
        的 sources 里,按五列比会把该过的地址判成对不上(评审 P2-1)。
        没重建的源在查询接口的观测里:verdict 为 malicious 的源名集合
        须是入库 sources 去掉被重建源之后的子集(扫描没漏指控者);入库
        sources 去掉被重建源之后须落在这些观测的源名里(入库没有多出
        查询接口看不到的源);malicious 观测的分类须都在入库 classes 里
        (入库 classes 可以多 —— 少掉的只能是随被重建源一起消失的分类);
        没被重建的证人,如果是良性断言(会注进每个指控组)、或者它的分类
        在入库 classes 里(所在的组扫描时是恶意组),须在入库 sources 里
        (扫描没漏证人)。
        满足 = 这个地址只核对了没被重建的源(入库 sources 去掉被重建源
        之后为空 = 本轮没有核对),计入 drift_skipped 并记例子,不中止。
      - 其余对不上:扫描器或入库有问题,停(GeoMismatchError)。
    返回 geo_stats:{"looked_up", "verified", "drift_skipped", "drift_examples",
    "changed_sources", "elapsed_s", "peak_rss_anon_mb"}。verified =
    looked_up - drift_skipped = 逐列核对过的地址数。
    """
    started = time.monotonic()
    limit = max(emit_tiers.TIERS)
    candidates = [row[0] for row in db.execute(
        f"SELECT ip FROM units WHERE {emit_tiers.TIER_WHERE} "
        f"ORDER BY {emit_tiers.TIER_ORDER_BY} LIMIT ?", (limit,))]
    candidates.sort(key=_ip_sort_key)     # 补查按 IP 数值序(随机读局部性)

    os.environ["IP_RADAR_POOL_CHILD"] = "1"
    from ipdb import load_db, lookup, _registry
    load_db()
    enabled = list(_registry._enabled_sources())
    allowed = frozenset(s.name for s in enabled
                        if s.name not in _registry._PRIVATE)
    # 只在 geo 开头读一次 ptr:下面的 lookup() 读的是 load_db() 这一刻开的
    # 纪元,geo 途中再有源被重建也读不到新数据,重算认不出新的「被重建的
    # 源」;反而可能把「geo 途中才被重建的源」上的真问题认成可以跳过
    # (复评 P3-5)。
    changed = _sources_changed_since_scan(epochs or {}, enabled)

    columns = ("verdict", "confidence", "classes", "sources", "source_count")
    mismatches: list[str] = []
    drift_examples: list[str] = []
    drift_skipped = 0
    peak_anon = scan_units._current_anon_rss_mb()
    looked_up = 0
    for ip in candidates:
        if looked_up % 500 == 0 and looked_up:
            peak_anon = max(peak_anon, scan_units._current_anon_rss_mb())
            if peak_anon > max_rss_mb:
                raise scan_units.MemoryBudgetExceeded(
                    f"geo 阶段匿名内存 {peak_anon:.1f}MB 超过预算 "
                    f"{max_rss_mb}MB(load_db 之后的引擎常驻数据)")
        looked_up += 1
        result = lookup(ip, allowed_sources=allowed,
                        asof=asof).to_dict()
        verdict, confidence, classes, sources, source_count, asn, country = \
            scan_units.extract_fields(result)
        db.execute("UPDATE units SET asn = ?, country = ? WHERE ip = ?",
                   (asn, country, ip))
        stored = db.execute(
            "SELECT verdict, confidence, classes, sources, source_count"
            " FROM units WHERE ip = ?", (ip,)).fetchone()
        computed = (verdict, confidence, classes, sources, source_count)
        parts = [f"{name} 入库={_short(old)} 查询接口={_short(new)}"
                 for name, old, new in zip(columns, stored, computed)
                 if old != new]
        if parts:
            stored_sources = _names(stored[3])
            stored_classes = _names(stored[2])
            rebuilt = (stored_sources | _names(sources)) & changed
            if rebuilt:
                # 证据里有被重建过的源:只核对没被重建的那部分(按观测比)
                kept = _registry.collect(ip,
                                         allowed_sources=allowed - changed)
                accusers = {o.source for o in kept.observations
                            if o.verdict == "malicious"}
                witnesses = {o.source for o in kept.observations
                             if o.verdict != "malicious"}
                kept_types = {o.classification_type
                              for o in kept.observations
                              if o.verdict == "malicious"
                              and o.classification_type}
                # 扫描时进过恶意组的证人(复评 P3-1):良性断言会注进每个
                # 指控组;分类在入库 classes 里的证人,所在的组扫描时是
                # 恶意组 —— 这两种证人扫描时都该进入库 sources
                missing = {
                    o.source for o in kept.observations
                    if o.verdict != "malicious"
                    and (o.verdict == "benign"
                         or o.classification_type in stored_classes)
                    and o.source not in stored_sources - changed}
                if (accusers <= stored_sources - changed
                        and stored_sources - changed <= accusers | witnesses
                        and kept_types <= stored_classes
                        and not missing):
                    drift_skipped += 1
                    note = ("入库证据全部来自被重建的源,本轮没有核对"
                            if not stored_sources - changed
                            else "只核对了没被重建的源")
                    drift_examples.append(
                        f"{ip}: {'; '.join(parts)}"
                        f"(涉及被重建的源: {', '.join(sorted(rebuilt))};{note})")
                    continue
            mismatches.append(f"{ip}: {'; '.join(parts)}")
            if len(mismatches) >= _MISMATCH_EXAMPLES:
                break
    db.commit()
    peak_anon = max(peak_anon, scan_units._current_anon_rss_mb())
    if mismatches:
        raise GeoMismatchError(
            "geo 阶段判定核对失败:扫描入库值与查询接口不一致(停下前查了"
            f"{looked_up} 个,列出前 {len(mismatches)} 例)—— "
            + "; ".join(mismatches),
            looked_up=looked_up, examples=mismatches,
            verified=looked_up - drift_skipped - len(mismatches),
            peak_rss_anon_mb=peak_anon,
            changed_sources=sorted(changed), drift_skipped=drift_skipped,
            drift_examples=drift_examples[:_MISMATCH_EXAMPLES])
    return {"looked_up": looked_up,
            "verified": looked_up - drift_skipped,
            "drift_skipped": drift_skipped,
            "drift_examples": drift_examples[:_MISMATCH_EXAMPLES],
            "changed_sources": sorted(changed),
            "elapsed_s": time.monotonic() - started,
            "peak_rss_anon_mb": peak_anon}


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    out_dir = Path(args.out_dir)
    staging = out_dir / ".staging"
    started = time.monotonic()
    # 开跑时刻钉死(--asof 或当下),扫描融合与 geo 补查用同一时刻,
    # 时间衰减两边一致;写进清单(规格 §5)。
    asof = float(args.asof) if args.asof is not None else time.time()
    stage = "init"
    stage_s: dict = {}
    stage_started = started
    scan_stats: dict | None = None
    geo_stats: dict | None = None
    db: sqlite3.Connection | None = None
    try:
        stage = "staging"
        _unlink_manifest_tmp(out_dir)     # kill 残留的 tmp(同陈旧 work.db 清理)
        staging.mkdir(parents=True, exist_ok=True)
        _unlink_work_db(staging)          # 中止轮次的陈旧 work.db
        db = sqlite3.connect(staging / "work.db")
        db.execute(UNITS_DDL)
        for column in CONSENSUS_COLUMNS:
            db.execute(f"ALTER TABLE units ADD COLUMN {column}")
        db.commit()

        stage = "scan"
        # 旗标即真相:显式 --data-dir 覆盖任何继承的 IP_RADAR_DATA_DIR,
        # registry 在子进程首次 import 时消费的就是它(import_engine 的
        # setdefault 随后成为 no-op)。
        os.environ["IP_RADAR_DATA_DIR"] = str(args.data_dir)
        scan_units.import_engine(args.data_dir, Path(args.engine_path))
        scan_stats = scan_units.scan_units(
            args.data_dir, db, asof=asof, log=_log)
        if scan_stats["units_total"] == 0:
            # 零单元 = 手上没有证据,不发空档位:空档位会被宿主的 push.sh
            # 发成 Release,下游读成「今天没有恶意 IP」。常见原因是数据卷
            # 没挂对,或引擎数据目录是空的(#444 评审 P2-1)。
            raise scan_units.ScanUnitsError(
                "扫描出 0 个单元,不发空档位——先查数据卷有没有挂对、"
                "引擎数据目录是不是空的(生产约 553 万个单元)")
        stage_s["scan"] = round(time.monotonic() - stage_started, 3)
        stage_started = time.monotonic()
        _log(f"[scan] units_total={scan_stats['units_total']}"
             f" units_v4={scan_stats['units_v4']}"
             f" units_v6={scan_stats['units_v6']}"
             f" units_cidr={scan_stats['units_cidr']}"
             f" malicious={scan_stats['malicious']}"
             f" records_total={scan_stats['records_total']}"
             f" skipped_anomalies={scan_stats['skipped_anomalies']}"
             f" peak_rss_anon_mb={scan_stats['peak_rss_anon_mb']:.1f}"
             f" elapsed_s={scan_stats['elapsed_s']:.1f}")

        stage = "geo"
        geo_stats = _geo_fill_and_verify(
            db, asof=asof, max_rss_mb=args.max_rss_mb,
            epochs=scan_stats["epochs"])
        stage_s["geo"] = round(time.monotonic() - stage_started, 3)
        stage_started = time.monotonic()
        _log(f"[geo] looked_up={geo_stats['looked_up']}"
             f" verified={geo_stats['verified']}"
             f" drift_skipped={geo_stats['drift_skipped']}"
             f" changed_sources={','.join(geo_stats['changed_sources']) or '-'}"
             f" peak_rss_anon_mb={geo_stats['peak_rss_anon_mb']:.1f}"
             f" elapsed_s={geo_stats['elapsed_s']:.1f}")

        stage = "emit"
        manifest = emit_tiers.emit_tiers(db, out_dir, staging_dir=staging)
        stage_s["emit"] = round(time.monotonic() - stage_started, 3)
        _log(f"[emit] malicious_pool={manifest['malicious_pool']}"
             f" tiers={manifest['tiers']} -> {out_dir}")
        db.close()
        db = None
        _unlink_work_db(staging)
        _close_staging(staging)

        # LEDGER RULING(T3 review):emit_tiers 成功 manifest 无 ctx 透传 —
        # 合并进其返回的 dict 并原子换入重写 manifest.json 本体(tmp +
        # os.replace,同 emit_tiers 发布路径:kill/ENOSPC 决不留撕裂文件)。
        stage = "manifest"
        manifest.update({
            "asof": asof,
            "epochs": scan_stats["epochs"],
            "scan_stats": scan_stats,
            "geo_stats": geo_stats,
            "stage_elapsed_s": stage_s,
            "elapsed_s": round(time.monotonic() - started, 3),
            # 双口径峰值(T7):peak_rss_mb = ru_maxrss 总量(含可回收 mmap
            # 文件页,仅观测);peak_rss_anon_mb = scan 逐批采样与 geo 采样
            # 两段的匿名内存最大值(--max-rss-mb 红线口径;当前采样非内核
            # 峰值,间隔尖峰归 cgroup)。
            "peak_rss_mb": round(scan_units._current_rss_mb(), 1),
            "peak_rss_anon_mb": round(max(
                scan_stats.get("peak_rss_anon_mb", 0.0),
                geo_stats.get("peak_rss_anon_mb", 0.0)), 1),
        })
        tmp = out_dir / "manifest.json.tmp"
        tmp.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, out_dir / "manifest.json")
        print(json.dumps(manifest, indent=2))
        return 0
    except Exception as exc:              # 任何阶段:响亮失败,不碰已发布产物
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        _unlink_work_db(staging)
        _close_staging(staging)
        error = f"[{stage}] {type(exc).__name__}: {exc}"
        ctx: dict = {"stage": stage,
                     "elapsed_s": round(time.monotonic() - started, 3),
                     "asof": asof}
        if scan_stats is not None:
            ctx["scan_stats"] = scan_stats
        if geo_stats is not None:
            ctx["geo_stats"] = geo_stats
        elif isinstance(exc, GeoMismatchError):
            # 核对失败时 geo_stats 还没返回:把停下之前的进度带出来
            ctx["geo_stats"] = {
                "looked_up": exc.looked_up,
                "verified": exc.verified,
                "mismatch_examples": exc.examples,
                "peak_rss_anon_mb": exc.peak_rss_anon_mb,
                "drift_skipped": exc.drift_skipped,
                "drift_examples": exc.drift_examples,
                "changed_sources": exc.changed_sources}
        try:
            emit_tiers.write_error_manifest(out_dir, error, **ctx)
            payload = json.loads(
                (out_dir / "manifest.json").read_text(encoding="utf-8"))
        except Exception as exc2:         # 连 error manifest 都写不下去了
            payload = {"error": f"{error} (error-manifest write failed:"
                                f" {exc2})"}
        print(json.dumps(payload, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
