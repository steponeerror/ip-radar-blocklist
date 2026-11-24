#!/usr/bin/env python3
"""按键序扫描单元提取器(#444 B 步)— 管线 scan 阶段.

替代 universe_walk(宇宙枚举)+ consensus_client(逐 IP 调查询接口):
调引擎的按键序扫描器(backend/ipdb/_scan.py 的 open_unit_scanner,#444
A 步)把各源库按键序读一遍、归并出每个单元的证据、用与查询接口同一套
融合代码算判定,逐单元写 sqlite units 表。判定五列(verdict、confidence、
classes、sources、source_count)由扫描结果按原 _extract_fields 规则填;
asn、country 扫描阶段留 NULL(扫描按规格不读地理库),geo 阶段只给进榜
IP 补查回写(见 generate_blocklist.py)。

内存红线不变(T7 口径):批量 executemany + commit,每批之后量一次匿名
RSS(smaps_rollup `Anonymous:` 行,解析失败回退 ru_maxrss 并告警一次),
超过 max_rss_mb 抛 MemoryBudgetExceeded —— 爆顶死任务不死机器。

引擎导入合同:IP_RADAR_DATA_DIR 在 registry import 期消费,必须先于
第一个 import ipdb 设置 —— import_engine 从 data_dir 参数惰性完成
(setdefault:已导入的进程(测试)沿用模块缓存);engine_path 进 sys.path
同在 import_engine。require_scan_engine 探测引擎镜像里有没有 _scan 模块:
没有 = 引擎镜像早于 #444,响亮报错让操作人先重建引擎镜像。
"""
from __future__ import annotations

import os
import resource
import sqlite3
import sys
import time
from pathlib import Path

BATCH_ROWS = 2000   # 内存红线:executemany 批上限,单元集只存在 sqlite 里

# PRIMARY KEY 冲突合并(原 universe_walk._UPSERT 加共识列):last_seen 取
# max、first_seen 取 min(ISO 文本,NULL 不参与比较、也不覆盖已有值)。
# 同单元跨源证据只出一行(排序确定性依赖此语义)。sqlite 标量 min()/max()
# 是 NULL 中毒的,故用与 last_seen 同款的 CASE 显式分支。共识列冲突不更新
# (扫描器按地址归并,同一单元文本不会产出两次;真撞上时保留先入库值)。
_UPSERT = """
INSERT INTO units(ip, is_v6, is_cidr, last_seen, first_seen,
                  verdict, confidence, classes, sources, source_count,
                  asn, country)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
    last_seen = CASE
        WHEN excluded.last_seen IS NOT NULL
             AND (units.last_seen IS NULL
                  OR excluded.last_seen > units.last_seen)
        THEN excluded.last_seen
        ELSE units.last_seen
    END,
    first_seen = CASE
        WHEN excluded.first_seen IS NOT NULL
             AND (units.first_seen IS NULL
                  OR excluded.first_seen < units.first_seen)
        THEN excluded.first_seen
        ELSE units.first_seen
    END
"""

# T7 自检指标源:匿名内存。ru_maxrss 总量把 LMDB 走读留下的可回收 mmap
# 文件页也算进去,会误杀;路径常量即测试注入接缝。
_SMAPS_ROLLUP_PATH = "/proc/self/smaps_rollup"
_anon_rss_fallback_warned = False          # 回退告警每进程只发一次


class MemoryBudgetExceeded(RuntimeError):
    """匿名 RSS 自检超过 max_rss_mb 预算(每批提交后检查;口径见
    _current_anon_rss_mb)。"""


class ScanUnitsError(RuntimeError):
    """scan 阶段永久性失败:引擎镜像太旧(require_scan_engine)、
    单元行缺 verdict(extract_fields)。"""


def _current_rss_mb() -> float:
    """ru_maxrss → MB(Linux 单位 KB,macOS 单位字节)。"""
    kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return kb / (1024 * 1024) if sys.platform == "darwin" else kb / 1024


def _current_anon_rss_mb() -> float:
    """匿名 RSS(MB):smaps_rollup 的 `Anonymous:` 行(kB → MB)。

    红线口径(T7):这是**当前采样值**,非内核维护峰值 —— 采样间隔间的
    尖峰是 cgroup 硬顶(mem_limit 150m)的职责。任何读取/解析失败(文件
    缺、行缺、值非整数)→ stderr 告警一次后回退 ru_maxrss 总量(旧口径,
    _current_rss_mb):指标降级响亮,绝不崩溃。"""
    global _anon_rss_fallback_warned
    try:
        with open(_SMAPS_ROLLUP_PATH, encoding="ascii") as fh:
            for line in fh:
                if line.startswith("Anonymous:"):
                    return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        pass                                   # 缺文件/缺行/非整数 → 回退
    if not _anon_rss_fallback_warned:
        _anon_rss_fallback_warned = True
        print(f"[scan] WARNING: cannot parse Anonymous from"
              f" {_SMAPS_ROLLUP_PATH} — anon-RSS self-check falls back to"
              f" ru_maxrss total", file=sys.stderr, flush=True)
    return _current_rss_mb()


def import_engine(data_dir: Path, engine_path: Path):
    """Set IP_RADAR_DATA_DIR (registry import-time consume) + inject the
    engine backend into sys.path, then import and return ipdb._sources._lmdb.

    setdefault: already-imported processes (tests) keep their module cache;
    dotenv at registry import never overrides a pre-set value, so ours wins.
    """
    os.environ.setdefault("IP_RADAR_DATA_DIR", str(data_dir))
    ep = str(engine_path)
    if ep not in sys.path:
        sys.path.insert(0, ep)
    from ipdb._sources import _lmdb
    return _lmdb


def require_scan_engine():
    """探测引擎镜像有没有按键序扫描器(#444 A 步的 ipdb._scan)。

    没有 = 引擎镜像早于 #444:响亮报错,提示先重建引擎镜像再跑导出,
    不裸抛 ImportError(操作人看得出是镜像旧,不是数据坏)。"""
    try:
        from ipdb._scan import open_unit_scanner
    except ImportError as exc:
        raise ScanUnitsError(
            "引擎镜像早于 #444,先重建引擎镜像再跑导出"
            f"(ipdb._scan 不可导入: {exc})") from exc
    return open_unit_scanner


def _merged_str(row: dict, field: str) -> str:
    """MergedField 胜者 str(value);字段或 value 缺失留空(裁决:缺失留空)。"""
    value = (row.get(field) or {}).get("value")
    return "" if value is None else str(value)


def extract_fields(row: dict) -> tuple:
    """lookup result → (verdict, confidence, classes, sources, source_count,
    asn, country),按 Global Constraints 入选口径(原 consensus_client
    _extract_fields,规则一字不改):

    - verdict = threat.verdict(全行存储,含 suspicious/benign/reserved);
    - 仅 malicious 行计数值字段:source_count/classes/sources 取「全部
      detected ∧ verdict=="malicious" 的 classification」里 distinct 源名
      与 type 并集;confidence = max malicious classification confidence;
    - 非 malicious 行数值/列表字段 NULL(suspicious 不入选,仅留 verdict)。
    """
    threat = row.get("threat") or {}
    verdict = threat.get("verdict")
    if not verdict:
        # 无 verdict 行若落库 NULL 会永远留在待补集合里 → 分页死循环。
        # 协议破损,响亮失败。
        raise ScanUnitsError(
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
    # confidence: 所有恶意分类中的最大值(与平台 UI 一致;threat.confidence
    # 在多分类同 verdict 时按字典序碰运气,非确定性——不用)
    max_conf = max(
        (cls.get("confidence") for cls in (row.get("classifications") or {}).values()
         if cls.get("detected") and cls.get("verdict") == "malicious"
         and isinstance(cls.get("confidence"), (int, float))),
        default=None)
    return (verdict, max_conf,
            ";".join(sorted(classes)), ";".join(sorted(src_names)),
            len(src_names), _merged_str(row, "asn"), _merged_str(row, "country"))


def scan_units(data_dir, db: sqlite3.Connection, *, asof,
               spill_dir=None, batch_rows: int = BATCH_ROWS,
               max_rss_mb: int = 140, log=None) -> dict:
    """按键序扫描全部启用源(减私源),把每个单元一行写进 caller 已建好的
    units 表(全 12 列契约;asn/country 留 NULL,geo 阶段补查回写)。

    asof(epoch 秒)钉死判定时刻:扫描融合与 geo 阶段补查用同一时刻,
    时间衰减两边一致。spill_dir=None → 扫描器自建临时目录。每 batch_rows
    个单元 executemany + commit,提交后量一次匿名内存,超 max_rss_mb 抛
    MemoryBudgetExceeded(已提交的批次保留,其余单元不再写)。

    引擎导入合同见模块 docstring:调方先 import_engine 设 env/sys.path;
    本函数 setdefault 兜底 env,并经 require_scan_engine 探测 _scan 模块。
    返回 stats:单元数(units_total/v4/v6/single/cidr 与扫描器自报的
    scanner_units)、malicious 数、records_total(读了几条记录)、
    skipped_anomalies、anomalous_records、skipped_geo_sources、elapsed_s、
    peak_rss_anon_mb、epochs(各库纪元号)、asof。
    """
    os.environ.setdefault("IP_RADAR_DATA_DIR", str(data_dir))
    open_unit_scanner = require_scan_engine()
    started = time.monotonic()
    stats: dict = {
        "units_total": 0, "units_v4": 0, "units_v6": 0,
        "units_single": 0, "units_cidr": 0, "scanner_units": {},
        "malicious": 0, "records_total": 0,
        "skipped_anomalies": 0, "anomalous_records": 0,
        "skipped_geo_sources": [],
        "elapsed_s": 0.0, "peak_rss_anon_mb": 0.0,
        "epochs": {}, "asof": asof,
    }
    scan_log = log if log is not None else (lambda msg: None)
    batch: list[tuple] = []
    scanned = 0
    with open_unit_scanner(asof=asof, spill_dir=spill_dir) as sc:
        for unit in sc:
            verdict, confidence, classes, sources, source_count, _, _ = \
                extract_fields(unit.result.to_dict())
            batch.append((
                unit.ip, 1 if unit.is_v6 else 0, 1 if unit.is_cidr else 0,
                unit.last_seen, unit.first_seen,
                verdict, confidence, classes, sources, source_count,
                None, None))       # asn/country:扫描不读地理库,留 NULL
            scanned += 1
            if len(batch) >= batch_rows:
                db.executemany(_UPSERT, batch)
                batch.clear()
                db.commit()
                _self_check_rss(stats, max_rss_mb)
                if scanned % (batch_rows * 50) == 0:
                    scan_log(f"[scan] units={scanned}"
                             f" elapsed_s={time.monotonic() - started:.0f}")
        if batch:
            db.executemany(_UPSERT, batch)
            batch.clear()
            db.commit()
            _self_check_rss(stats, max_rss_mb)
        stats["epochs"] = {name: list(epochs)
                           for name, epochs in sc.epochs.items()}
        scanner_stats = sc.stats
    stats["scanner_units"] = dict(scanner_stats["units"])
    stats["skipped_anomalies"] = scanner_stats["skipped_anomalies"]
    stats["anomalous_records"] = scanner_stats["anomalous_records"]
    stats["skipped_geo_sources"] = list(scanner_stats["skipped_geo_sources"])
    stats["records_total"] = (sum(scanner_stats["records"].values())
                              + sum(scanner_stats["cidr_records"].values()))

    def _count(sql: str) -> int:
        return db.execute(sql).fetchone()[0]

    stats["units_total"] = _count("SELECT COUNT(*) FROM units")
    stats["units_v4"] = _count("SELECT COUNT(*) FROM units WHERE is_v6 = 0")
    stats["units_v6"] = _count("SELECT COUNT(*) FROM units WHERE is_v6 = 1")
    stats["units_single"] = _count(
        "SELECT COUNT(*) FROM units WHERE is_cidr = 0")
    stats["units_cidr"] = _count(
        "SELECT COUNT(*) FROM units WHERE is_cidr = 1")
    stats["malicious"] = _count(
        "SELECT COUNT(*) FROM units WHERE verdict = 'malicious'")
    stats["elapsed_s"] = time.monotonic() - started
    return stats


def _self_check_rss(stats: dict, max_rss_mb: int) -> None:
    """逐批匿名内存自检:峰值 = 各批采样 max;超预算响亮中止。"""
    anon_mb = _current_anon_rss_mb()
    stats["peak_rss_anon_mb"] = max(stats["peak_rss_anon_mb"], anon_mb)
    if anon_mb > max_rss_mb:
        raise MemoryBudgetExceeded(
            f"anon RSS {anon_mb:.1f}MB exceeds budget {max_rss_mb}MB")
