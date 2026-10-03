#!/usr/bin/env python3
"""档位产出器 — sorted malicious pool → nested top_N.{txt,csv} + manifest.

Nightly blocklist pipeline stage 3 (plan 2026-10-03-blocklist-pipeline-v1
T3): rank the enriched units 表 (verdict == "malicious" only) by the Global
Constraints key chain (Q2-B 全源口径) and slice nested supersets per tier —
every tier re-runs the SAME single sorted SQL with only a different LIMIT,
so tier files are guaranteed-consistent prefixes of one ranking. Files
always exist ("up to N"): pool smaller than a tier → fewer rows; pool 0 →
empty txt + header-only csv.

Memory redline: rows stream straight off the sqlite cursor into the staged
files — the pool is never materialized into a Python list/dict (plan Global
Constraints). Publish is atomic: everything lands in .staging/ first
(gitignored), is verified (per-tier on-disk row counts), then os.replace'd
into out_dir one file at a time with manifest.json LAST — it is the
consumer-visible commit point. Failure contract: write_error_manifest()
overwrites ONLY manifest.json; after an emit_tiers() exception the staging
leftovers are the caller's decision (Task 4 error path).
"""
from __future__ import annotations

import csv
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# CSV 8 列表头逐字(first_seen 在 source_count 与
# last_seen 之间);SELECT 列序与之一一对应
CSV_HEADER = ("ip", "asn", "country", "classes", "confidence",
              "source_count", "first_seen", "last_seen")

# 单条排序 SQL(Q2-B):source_count DESC → confidence DESC →
# last_seen NULLS LAST(SQLite 无 NULLS LAST 关键字,`last_seen IS NULL`
# 得 0/1,ASC 即非 NULL 在前)→ last_seen DESC 最新优先 → ip ASC 终键保
# 跨轮确定性。全档位共用,仅 LIMIT 不同 → 嵌套超集恒成立。
_TIER_SQL = f"""
SELECT {", ".join(CSV_HEADER)}
FROM units
WHERE verdict = 'malicious'
ORDER BY source_count DESC, confidence DESC,
         last_seen IS NULL ASC, last_seen DESC, ip ASC
LIMIT ?
"""


def _utc_now_iso() -> str:
    """ISO 8601 UTC 时间戳(秒精度,+00:00 后缀)。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _scalar(db: sqlite3.Connection, sql: str) -> int:
    return db.execute(sql).fetchone()[0]


def _pool_count(db: sqlite3.Connection, cond: str) -> int:
    """恶意池内计数(cond 仅来自本模块字面量,非外部输入)。"""
    return _scalar(db, f"SELECT COUNT(*) FROM units"
                       f" WHERE verdict = 'malicious' AND ({cond})")


def _write_tier(db: sqlite3.Connection, txt_path: Path, csv_path: Path,
                limit: int) -> int:
    """Stream the LIMIT-n sorted cursor → txt + csv. Returns rows written.

    txt:每行 ip 列原文(CIDR/v6 混装),无表头无注释,行尾 LF、EOF 恰一
    换行;csv:表头逐字 9 列,QUOTE_MINIMAL(逗号字段自动引),NULL → ""。
    """
    rows = 0
    with open(txt_path, "w", encoding="utf-8", newline="\n") as tf, \
            open(csv_path, "w", encoding="utf-8", newline="") as cf:
        writer = csv.writer(cf, lineterminator="\n")   # QUOTE_MINIMAL 默认
        writer.writerow(CSV_HEADER)
        for row in db.execute(_TIER_SQL, (limit,)):
            tf.write(row[0] + "\n")
            writer.writerow("" if v is None else v for v in row)
            rows += 1
    return rows


def _verify_staged(staging: Path, tiers: tuple, pool: int) -> None:
    """发布前校验:每档 staged 落盘行数 = min(N, 池)。任何不符 → 不换入。"""
    for n in tiers:
        expected = min(n, pool)
        with open(staging / f"top_{n}.txt", "rb") as f:
            txt_rows = 0
            while chunk := f.read(1 << 16):
                txt_rows += chunk.count(b"\n")   # ip 文本无内嵌换行
        with open(staging / f"top_{n}.csv", newline="",
                  encoding="utf-8") as f:
            csv_rows = sum(1 for _ in csv.reader(f)) - 1   # 减表头
        if txt_rows != expected or csv_rows != expected:
            raise RuntimeError(
                f"tier {n}: staged txt={txt_rows} csv={csv_rows} rows,"
                f" expected {expected} (malicious pool={pool})"
                " — refusing to publish")


def emit_tiers(db: sqlite3.Connection, out_dir: Path, *,
               tiers: tuple = (100, 500, 1000, 5000, 10000),
               staging_dir: Path | None = None) -> dict:
    """Rank the malicious pool, slice nested tiers, atomically publish.

    写 <staging>/top_N.{txt,csv}(staging 默认 <out_dir>/.staging)→ 逐档
    校验行数 = min(N, 恶意池) → 逐文件 os.replace 换入 out_dir,
    manifest.json 最后落(消费者可见提交点)→ staging 收尾(我方文件已随
    replace 移走,他人内容不动,仅尽力 rmdir)。返回 manifest dict;
    异常向上抛(staging 残留由调方处置,见 Task 4 error 路径)。
    """
    out_dir = Path(out_dir)
    staging = Path(staging_dir) if staging_dir is not None \
        else out_dir / ".staging"
    out_dir.mkdir(parents=True, exist_ok=True)
    staging.mkdir(parents=True, exist_ok=True)

    pool = _scalar(db, "SELECT COUNT(*) FROM units"
                       " WHERE verdict = 'malicious'")
    manifest = {
        "generated_at": _utc_now_iso(),
        "tiers": {},
        "universe": _scalar(db, "SELECT COUNT(*) FROM units"),
        "malicious_pool": pool,
        "cidr_units": _pool_count(db, "is_cidr = 1"),
        "units_v6": _pool_count(db, "is_v6 = 1"),
        "first_seen_coverage": _pool_count(
            db, "first_seen IS NOT NULL") / pool if pool else 0.0,
    }

    # 流式写档:每档一条 LIMIT 游标,行到即写,池从不物化
    for n in tiers:
        manifest["tiers"][str(n)] = _write_tier(
            db, staging / f"top_{n}.txt", staging / f"top_{n}.csv", n)

    _verify_staged(staging, tiers, pool)

    manifest_path = staging / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # 原子换入:逐文件 os.replace;manifest.json 最后 = 提交点
    for n in tiers:
        os.replace(staging / f"top_{n}.txt", out_dir / f"top_{n}.txt")
        os.replace(staging / f"top_{n}.csv", out_dir / f"top_{n}.csv")
    os.replace(manifest_path, out_dir / "manifest.json")

    try:                                       # 空则除名;余他人内容则保留
        staging.rmdir()
    except OSError:
        pass
    return manifest


def write_error_manifest(out_dir: Path, error: str, **ctx) -> None:
    """失败契约:仅覆写 manifest.json(error + **ctx 透传 + generated_at),
    绝不碰其他产物文件——消费者从此读到显式错误态,而非半新半旧产物。
    Task 4 在任何管线失败路径调用(walk/enrich stats 等经 **ctx 传入)。
    写入走 tmp + os.replace(同发布路径):kill/ENOSPC 也不留撕裂 manifest。
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {"error": error, **ctx, "generated_at": _utc_now_iso()}
    tmp = out_dir / "manifest.json.tmp"
    tmp.write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, out_dir / "manifest.json")
