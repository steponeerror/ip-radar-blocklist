#!/usr/bin/env python3
"""宇宙枚举器 — stream every engine LMDB threat shard into the sqlite units 表.

Nightly blocklist pipeline stage 1 (plan 2026-10-03-blocklist-pipeline-v1 T1):
cursor-scan each threat source's v4/v6 epoch envs (precedent: engine
``scripts/verify_watermark.py::_layer2``) and upsert one row per
evidence-bearing unit. Memory redline: nothing but a ≤500-row executemany
batch is ever held in Python — the unit set lives only in sqlite.

Engine import contract: ``IP_RADAR_DATA_DIR`` is consumed by
``ipdb._registry`` AT IMPORT TIME (and ``load_dotenv(backend/.env)`` never
overrides an already-set var), so it must be exported before the first
``import ipdb...`` — done lazily inside ``_import_engine`` from the
``data_dir`` argument, never at module import.
"""
from __future__ import annotations

import ipaddress
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterator

BATCH_SIZE = 500   # 内存红线:executemany 批上限,单元集只存在 sqlite 里

# PRIMARY KEY 冲突合并:last_seen 取 max(NULL 不参与、不覆盖已有值),
# has_first_seen 取 OR —— 同单元跨源证据只出一行(排序确定性依赖此语义)。
_UPSERT = """
INSERT INTO units(ip, is_v6, is_cidr, last_seen, has_first_seen)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
    last_seen = CASE
        WHEN excluded.last_seen IS NOT NULL
             AND (units.last_seen IS NULL
                  OR excluded.last_seen > units.last_seen)
        THEN excluded.last_seen
        ELSE units.last_seen
    END,
    has_first_seen = MAX(units.has_first_seen, excluded.has_first_seen)
"""


def _import_engine(data_dir: Path, engine_path: Path):
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


def _is_threat_source(s: Any) -> bool:
    """威胁源判定(classification_type 非空 ∧ category=="threat" ∧ 非内部)。
    internal 哨兵(watermark canary)与 geo/asset 源都不进宇宙。"""
    return (getattr(s, "classification_type", None) is not None
            and getattr(s, "category", None) == "threat"
            and not getattr(s, "internal", False))


def _threat_sources() -> list:
    """Production source list: registry enumeration filtered to threat sources.

    测试缝(seam):单测 monkeypatch 本函数注入显式构造的源实例
    (DataplaneSource(tmp) 等),绕开 registry 的全源实例化。"""
    from ipdb import _registry
    return [s for s in _registry._sources if _is_threat_source(s)]


def _iter_records(lmdb_mod, base: Path, is_v6: bool,
                  stats: dict) -> Iterator[tuple]:
    """Stream one family env → (ip, is_v6, is_cidr, last_seen, has_first_seen).

    无 ptr(该族无分片)静默返回;PAYLOADS_NAME 是 payloads 命名库在主库
    键空间的描述符键,不是 [end, evidence] 记录,跳过;int 证据是
    interning ref,须在 txn 内经 resolve_evidence 解引用;区间 summarize
    结果 ≠ 恰 1 个 CIDR 记 anomaly 跳过(流式两步探测,不物化列表)。
    """
    epoch = lmdb_mod.read_ptr(base)
    if epoch is None:
        return
    env = lmdb_mod.open_env_read(base.parent / f"{base.name}.{epoch}")
    pay_db = lmdb_mod._payloads_db(env)     # txn 外取(open_env_read 已预热)
    addr_cls = ipaddress.IPv6Address if is_v6 else ipaddress.IPv4Address
    with env.begin() as txn:
        for key, raw in txn.cursor().iternext():
            if key == lmdb_mod.PAYLOADS_NAME:
                continue
            start = int.from_bytes(key, "big")
            end, ev = lmdb_mod.decode_value(raw)
            if isinstance(ev, int):
                ev = lmdb_mod.resolve_evidence(txn, ev, pay_db)
            # 一条记录的证据可能是 dict 或 dict 列表:字段跨列表聚合
            last_seen: str | None = None
            has_first_seen = 0
            for e in (ev if isinstance(ev, list) else [ev]):
                if not isinstance(e, dict):
                    continue
                ls = e.get("last_seen")
                if isinstance(ls, str) and (last_seen is None or ls > last_seen):
                    last_seen = ls          # ISO 文本,字典序即时间序
                if e.get("first_seen"):
                    has_first_seen = 1
            nets = ipaddress.summarize_address_range(
                addr_cls(start), addr_cls(end))
            net = next(nets, None)          # 两步探测:恰 1 个才收,免物化
            if net is None or next(nets, None) is not None:
                stats["skipped_anomalies"] += 1
                continue
            if net.prefixlen == net.max_prefixlen:   # /32、/128 写纯 IP
                text, is_cidr = str(net.network_address), 0
            else:
                text, is_cidr = str(net), 1
            yield (text, 1 if is_v6 else 0, is_cidr, last_seen, has_first_seen)


def walk_universe(data_dir: Path, db: sqlite3.Connection, *,
                  engine_path: Path) -> dict:
    """Enumerate the candidate universe into the caller-created units table.

    表(调方先建):units(ip TEXT PRIMARY KEY, is_v6 INTEGER NOT NULL,
    is_cidr INTEGER NOT NULL, last_seen TEXT,
    has_first_seen INTEGER NOT NULL DEFAULT 0)。
    返回 stats:{"units_total", "units_v4", "units_v6", "cidr_units",
    "per_source", "first_seen_coverage", "skipped_anomalies"}。
    """
    data_dir = Path(data_dir)
    lmdb_mod = _import_engine(data_dir, Path(engine_path))
    stats: dict = {"per_source": {}, "skipped_anomalies": 0}
    batch: list[tuple] = []
    for src in _threat_sources():
        for base, is_v6 in ((src._lmdb_base, False), (src._lmdb6_base, True)):
            for row in _iter_records(lmdb_mod, base, is_v6, stats):
                stats["per_source"][src.name] = \
                    stats["per_source"].get(src.name, 0) + 1
                batch.append(row)
                if len(batch) >= BATCH_SIZE:
                    db.executemany(_UPSERT, batch)
                    batch.clear()
    if batch:
        db.executemany(_UPSERT, batch)
    db.commit()

    def _count(sql: str) -> int:
        return db.execute(sql).fetchone()[0]

    total = _count("SELECT COUNT(*) FROM units")
    stats.update({
        "units_total": total,
        "units_v4": _count("SELECT COUNT(*) FROM units WHERE is_v6 = 0"),
        "units_v6": _count("SELECT COUNT(*) FROM units WHERE is_v6 = 1"),
        "cidr_units": _count("SELECT COUNT(*) FROM units WHERE is_cidr = 1"),
        "first_seen_coverage":
            _count("SELECT COUNT(*) FROM units WHERE has_first_seen = 1")
            / total if total else 0.0,
    })
    return stats
