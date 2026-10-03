#!/usr/bin/env python3
"""CLI 编排器 — nightly 黑名单导出全管线:walk → enrich → emit → manifest.

Nightly blocklist pipeline stage 4 (plan 2026-10-03-blocklist-pipeline-v1 T4):
wires the three stage modules together as one command:

    python scripts/generate_blocklist.py \
        --engine-path <backend> --data-dir <LMDB data> --api-base <engine URL> \
        [--out-dir .] [--max-rss-mb 140]

Orchestration: work db lives at ``<out_dir>/.staging/work.db`` (a real file,
not ``:memory:`` — it is the pipeline's only intermediate state and must
survive across stages; stale copies from aborted runs are deleted first).
The CLI creates the units 表 (T1 contract) and ALTERs the 7 consensus
columns in (T2 contract), then walks, enriches, and emits.

Manifest contract (T3 ledger ruling): ``emit_tiers``' success manifest has NO
ctx passthrough — this orchestrator merges the extra context (walk stats,
enrich stats, total elapsed, peak RSS, api base) into the RETURNED manifest
dict and rewrites ``manifest.json`` itself after the atomic publish.

Failure contract: ANY exception → ``write_error_manifest`` (only manifest.json
is touched; tier files from previous runs stay), the error manifest printed
to stderr, exit 1. 成功 → manifest JSON on stdout(机器可读,cron/CI 直吃),
每阶段一行带计数的进度走 stderr — stdout 永远只有 manifest。
"""
from __future__ import annotations

import argparse
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

from scripts import consensus_client, emit_tiers, universe_walk  # noqa: E402

DEFAULT_ENGINE_PATH = Path("/home/huxiao/dev/pi-ip-lookup-tool/backend")

# T1 契约:调方建表;T2 契约:调方 ALTER 共识列
UNITS_DDL = """
CREATE TABLE units(
    ip TEXT PRIMARY KEY,
    is_v6 INTEGER NOT NULL,
    is_cidr INTEGER NOT NULL,
    last_seen TEXT,
    has_first_seen INTEGER NOT NULL DEFAULT 0
)
"""
CONSENSUS_COLUMNS = ("verdict TEXT", "confidence INTEGER", "classes TEXT",
                     "sources TEXT", "source_count INTEGER", "asn TEXT",
                     "country TEXT")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Nightly ip-radar blocklist export: walk engine threat "
                    "shards → consensus-enrich via stream API → emit nested "
                    "top_N tiers + manifest (atomic publish).")
    p.add_argument("--engine-path", type=Path, default=DEFAULT_ENGINE_PATH,
                   help=f"ip-radar backend repo path (default: "
                        f"{DEFAULT_ENGINE_PATH}); imported read-only")
    p.add_argument("--data-dir", type=Path, required=True,
                   help="engine LMDB data dir (IP_RADAR_DATA_DIR)")
    p.add_argument("--api-base", required=True,
                   help="live engine base URL, e.g. http://127.0.0.1:8000")
    p.add_argument("--out-dir", type=Path, default=_REPO_ROOT,
                   help="artifact directory (default: repo root)")
    p.add_argument("--max-rss-mb", type=int, default=140,
                   help="ru_maxrss budget in MB; exceeding aborts the run "
                        "(default: 140)")
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


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    out_dir = Path(args.out_dir)
    staging = out_dir / ".staging"
    started = time.monotonic()
    stage = "init"
    walk_stats: dict | None = None
    enrich_stats: dict | None = None
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

        stage = "walk"
        # 旗标即真相:显式 --data-dir 覆盖任何继承的 IP_RADAR_DATA_DIR,
        # registry 在子进程首次 import 时消费的就是它(universe_walk 的
        # setdefault 随后成为 no-op)。
        os.environ["IP_RADAR_DATA_DIR"] = str(args.data_dir)
        walk_stats = universe_walk.walk_universe(
            args.data_dir, db, engine_path=Path(args.engine_path))
        _log(f"[walk] units_total={walk_stats['units_total']}"
             f" units_v4={walk_stats['units_v4']}"
             f" units_v6={walk_stats['units_v6']}"
             f" cidr_units={walk_stats['cidr_units']}"
             f" skipped_anomalies={walk_stats['skipped_anomalies']}")

        stage = "enrich"
        enrich_stats = consensus_client.enrich_with_consensus(
            db, args.api_base, max_rss_mb=args.max_rss_mb)
        _log(f"[enrich] queried={enrich_stats['queried']}"
             f" malicious={enrich_stats['malicious']}"
             f" requests={enrich_stats['requests']}"
             f" retries={enrich_stats['retries']}"
             f" elapsed_s={enrich_stats['elapsed_s']:.1f}")

        stage = "emit"
        manifest = emit_tiers.emit_tiers(db, out_dir, staging_dir=staging)
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
            "walk_stats": walk_stats,
            "enrich_stats": enrich_stats,
            "elapsed_s": round(time.monotonic() - started, 3),
            "peak_rss_mb": round(consensus_client._current_rss_mb(), 1),
            "api_base": args.api_base,
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
                     "api_base": args.api_base}
        if walk_stats is not None:
            ctx["walk_stats"] = walk_stats
        if enrich_stats is not None:
            ctx["enrich_stats"] = enrich_stats
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
