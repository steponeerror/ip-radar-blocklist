"""Task 3 tests — emit_tiers: sorted malicious pool → nested tier artifacts.

Fixture strategy: pure sqlite (engine untouched — T3 only reads the
post-T1+T2 enriched units 表, no LMDB, no API). 11 rows: 8 malicious
exercising every sort-key branch (source_count DESC, confidence DESC,
last_seen NULLS LAST, ip ASC tie pair) plus v6 / v4-CIDR / NULL-text-field
shapes, + 2 suspicious + 1 benign that must never leak into any artifact.
"""
import csv
import json
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))          # scripts/ as namespace pkg portion

from scripts import emit_tiers              # noqa: E402 (stdlib-only: pre-env safe)

MANDATORY_FIELDS = {"generated_at", "tiers", "universe", "malicious_pool",
                    "cidr_units", "units_v6", "first_seen_coverage"}
DEFAULT_TIERS = (100, 500, 1000, 5000, 10000)

UNITS_DDL = """
CREATE TABLE units(
    ip TEXT PRIMARY KEY,
    is_v6 INTEGER NOT NULL,
    is_cidr INTEGER NOT NULL,
    last_seen TEXT,
    first_seen TEXT,
    verdict TEXT,
    confidence INTEGER,
    classes TEXT,
    sources TEXT,
    source_count INTEGER,
    asn TEXT,
    country TEXT
)
"""

# 排序全链预期(Q2-B):sc DESC → conf DESC → last_seen NULLS LAST →
# last_seen DESC → ip ASC(同分对 "198.51.100.0/24" < "2001:db8::1")。
EXPECTED_ORDER = [
    "203.0.113.10",        # sc=4 — 唯一最高源数
    "203.0.113.20",        # sc=3, conf=90 — confidence DESC 胜出
    "203.0.113.0/24",      # sc=3, conf=60
    "203.0.113.40",        # sc=2, conf=70, ls=10-06 — last_seen DESC 最新
    "203.0.113.50",        # sc=2, conf=70, ls=10-02
    "203.0.113.60",        # sc=2, conf=70, ls=NULL — NULLS LAST
    "198.51.100.0/24",     # sc=1, conf=50, ls=NULL — 同分对 ip ASC('1'<'2')
    "2001:db8::1",         # 同分对另一端(v6 纯地址)
]


def _insert(conn, ip, *, verdict, is_v6=0, is_cidr=0, last_seen=None,
            first_seen=None, confidence=None, classes=None, sources=None,
            source_count=None, asn=None, country=None):
    conn.execute(
        "INSERT INTO units(ip, is_v6, is_cidr, last_seen, first_seen,"
        " verdict, confidence, classes, sources, source_count, asn, country)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (ip, is_v6, is_cidr, last_seen, first_seen, verdict, confidence,
         classes, sources, source_count, asn, country))


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.execute(UNITS_DDL)
    _insert(conn, "203.0.113.10", verdict="malicious", source_count=4,
            confidence=80, last_seen="2026-10-05T00:00:00Z",
            first_seen="2026-10-01T00:00:00Z",
            classes="scanner", sources="srcA;srcB;srcC;srcD",
            asn="AS64512, Example Net", country="US")     # asn 含逗号 → 引号
    _insert(conn, "203.0.113.20", verdict="malicious", source_count=3,
            confidence=90, last_seen="2026-10-04T00:00:00Z",
            first_seen="2026-09-20T00:00:00Z",
            classes="bruteforce", sources="srcA;srcB;srcC",
            asn="AS64513", country="DE")
    _insert(conn, "203.0.113.0/24", verdict="malicious", is_cidr=1,
            source_count=3, confidence=60,
            last_seen="2026-10-01T00:00:00Z",
            classes="spam", sources="srcB", asn="AS64514")
    _insert(conn, "203.0.113.40", verdict="malicious", source_count=2,
            confidence=70, last_seen="2026-10-06T00:00:00Z",
            first_seen="2026-09-25T00:00:00Z",
            asn="AS64515", country="JP")
    _insert(conn, "203.0.113.50", verdict="malicious", source_count=2,
            confidence=70, last_seen="2026-10-02T00:00:00Z",
            asn="AS64516", country="JP")
    _insert(conn, "203.0.113.60", verdict="malicious", source_count=2,
            confidence=70)                    # NULL last_seen/asn/country
    _insert(conn, "2001:db8::1", verdict="malicious", is_v6=1,
            source_count=1, confidence=50, asn="AS64517")
    _insert(conn, "198.51.100.0/24", verdict="malicious", is_cidr=1,
            source_count=1, confidence=50, asn="AS64518")
    # verdict 入库但不入选:任何产物/任何口径都不得出现这三行
    _insert(conn, "192.0.2.50", verdict="suspicious", confidence=99)
    _insert(conn, "192.0.2.51", verdict="suspicious")
    _insert(conn, "192.0.2.99", verdict="benign", confidence=100,
            source_count=9)
    return conn


@pytest.fixture
def out_dir(tmp_path):
    return tmp_path / "out"


def test_sort_chain_txt_purity_and_csv_verbatim(db, out_dir):
    emit_tiers.emit_tiers(db, out_dir)

    # 一次字节级断言钉死:排序全链顺序 + 无表头无注释 + LF + EOF 恰一换行 + UTF-8
    raw = (out_dir / "top_100.txt").read_bytes()
    assert raw == ("\n".join(EXPECTED_ORDER) + "\n").encode("utf-8")

    raw_csv = (out_dir / "top_100.csv").read_bytes()
    assert raw_csv.endswith(b"\n") and b"\r" not in raw_csv
    lines = raw_csv.split(b"\n")
    # 表头逐字 9 列(first_seen 在 sources 与 last_seen 之间)
    assert lines[0] == (b"ip,asn,country,classes,confidence,"
                        b"source_count,sources,first_seen,last_seen")
    # QUOTE_MINIMAL:asn 含逗号必须加引号(RFC4180)
    assert lines[1] == (b'203.0.113.10,"AS64512, Example Net",US,scanner,'
                        b'80,4,srcA;srcB;srcC;srcD,'
                        b'2026-10-01T00:00:00Z,2026-10-05T00:00:00Z')

    with open(out_dir / "top_100.csv", newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["ip", "asn", "country", "classes", "confidence",
                       "source_count", "sources", "first_seen", "last_seen"]
    assert [r[0] for r in rows[1:]] == EXPECTED_ORDER
    # NULL 字段 → 空字符串(m6 的 first_seen/last_seen/asn/country 皆 NULL)
    m6 = rows[1 + EXPECTED_ORDER.index("203.0.113.60")]
    assert m6 == ["203.0.113.60", "", "", "", "70", "2", "", "", ""]


def test_pool_smaller_than_tiers_up_to_n(db, out_dir):
    manifest = emit_tiers.emit_tiers(db, out_dir)
    for n in DEFAULT_TIERS:
        for suffix in ("txt", "csv"):
            assert (out_dir / f"top_{n}.{suffix}").exists(), (n, suffix)
        # 池 8 < 任何档位 → 每个文件恰 8 行("up to N",行数即真实数)
        assert (out_dir / f"top_{n}.txt").read_text().count("\n") == 8
    assert manifest["tiers"] == {str(n): 8 for n in DEFAULT_TIERS}


def test_tiers_are_nested_prefixes(db, out_dir):
    manifest = emit_tiers.emit_tiers(db, out_dir, tiers=(2, 5))
    t2 = (out_dir / "top_2.txt").read_text()
    t5 = (out_dir / "top_5.txt").read_text()
    assert t2.splitlines() == EXPECTED_ORDER[:2]
    assert t5.splitlines() == EXPECTED_ORDER[:5]
    assert t5.startswith(t2)                       # 嵌套超集 = 同一排序前缀
    with open(out_dir / "top_5.csv", newline="", encoding="utf-8") as f:
        assert [r[0] for r in csv.reader(f)][1:] == EXPECTED_ORDER[:5]
    assert manifest["tiers"] == {"2": 2, "5": 5}


def test_manifest_fields_and_file_agreement(db, out_dir):
    manifest = emit_tiers.emit_tiers(db, out_dir)
    on_disk = json.loads(
        (out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk == manifest                     # 返回值与落盘一致
    assert MANDATORY_FIELDS <= set(manifest)
    assert "error" not in manifest
    assert manifest["universe"] == 11              # 8 malicious + 2 sus + 1 ben
    assert manifest["malicious_pool"] == 8
    assert manifest["cidr_units"] == 2             # 203.0.113.0/24, 198.51.100.0/24
    assert manifest["units_v6"] == 1               # 2001:db8::1
    assert manifest["first_seen_coverage"] == pytest.approx(3 / 8)  # 非空占比
    # suspicious/benign 不进任何口径
    assert set(manifest["tiers"].values()) == {8}
    ts = datetime.fromisoformat(manifest["generated_at"])
    assert ts.utcoffset() == timedelta(0)          # ISO 8601 UTC


def test_default_staging_removed_after_success(db, out_dir):
    emit_tiers.emit_tiers(db, out_dir)
    staging = out_dir / ".staging"
    assert not staging.exists() or not any(staging.iterdir())


def test_custom_staging_dir_publishes_to_out_dir(db, out_dir, tmp_path):
    custom = tmp_path / "elsewhere" / "staging"
    manifest = emit_tiers.emit_tiers(db, out_dir, staging_dir=custom)
    assert manifest["malicious_pool"] == 8
    assert (out_dir / "top_100.txt").read_text().count("\n") == 8
    assert json.loads(
        (out_dir / "manifest.json").read_text())["tiers"]["100"] == 8
    assert not (out_dir / ".staging").exists()     # 默认 staging 从未创建
    assert not custom.exists() or not any(custom.iterdir())


def test_empty_pool_zero_byte_txt_and_header_only_csv(out_dir):
    conn = sqlite3.connect(":memory:")
    conn.execute(UNITS_DDL)
    _insert(conn, "192.0.2.1", verdict="suspicious")
    _insert(conn, "192.0.2.2", verdict="benign")
    manifest = emit_tiers.emit_tiers(conn, out_dir)
    for n in DEFAULT_TIERS:
        assert (out_dir / f"top_{n}.txt").read_bytes() == b""
        assert (out_dir / f"top_{n}.csv").read_bytes() == (
            b"ip,asn,country,classes,confidence,"
            b"source_count,sources,first_seen,last_seen\n")
    assert manifest["malicious_pool"] == 0
    assert manifest["first_seen_coverage"] == 0.0   # 除零守卫
    assert manifest["universe"] == 2
    assert manifest["tiers"] == {str(n): 0 for n in DEFAULT_TIERS}


def test_write_error_manifest_only_touches_manifest(out_dir):
    out_dir.mkdir(parents=True)
    good_txt = out_dir / "top_100.txt"
    good_txt.write_text("203.0.113.10\n", encoding="utf-8")
    (out_dir / "manifest.json").write_text('{"tiers": {"100": 8}}',
                                           encoding="utf-8")

    emit_tiers.write_error_manifest(
        out_dir, "enrich failed: engine 500",
        walk_stats={"units_total": 11}, elapsed_s=12.5)

    payload = json.loads(
        (out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert payload["error"] == "enrich failed: engine 500"
    assert payload["walk_stats"] == {"units_total": 11}   # **ctx 透传
    assert payload["elapsed_s"] == 12.5
    assert datetime.fromisoformat(
        payload["generated_at"]).utcoffset() == timedelta(0)
    assert good_txt.read_text(encoding="utf-8") == "203.0.113.10\n"  # 未动


def test_write_error_manifest_creates_missing_out_dir(tmp_path):
    out = tmp_path / "fresh"
    emit_tiers.write_error_manifest(out, "boom")
    assert json.loads((out / "manifest.json").read_text())["error"] == "boom"
