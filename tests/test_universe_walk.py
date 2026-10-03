"""Task 1 tests — universe_walk: LMDB threat shard → sqlite units enumeration.

Fixture strategy (engine read-only at /home/huxiao/dev/pi-ip-lookup-tool):
real engine source classes fed hand-written raw files, then ``rebuild()``
produces genuine epoch/ptr shards — the walker scans exactly what production
writes. IP_RADAR_DATA_DIR must be set BEFORE the first ``import ipdb...``
(the registry consumes it at import time), hence every engine import in
this file lives inside a fixture/test body after the ``data_dir`` fixture
sets the env var.
"""
import ipaddress
import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))          # scripts/ as namespace pkg portion

from scripts import universe_walk           # noqa: E402 (stdlib-only: pre-env safe)

ENGINE_BACKEND = Path("/home/huxiao/dev/pi-ip-lookup-tool/backend")

UNITS_DDL = """
CREATE TABLE units(
    ip TEXT PRIMARY KEY,
    is_v6 INTEGER NOT NULL,
    is_cidr INTEGER NOT NULL,
    last_seen TEXT,
    has_first_seen INTEGER NOT NULL DEFAULT 0
)
"""


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """tmp data dir + env var pinned before any ipdb import in this process."""
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setenv("IP_RADAR_DATA_DIR", str(d))
    return d


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.execute(UNITS_DDL)
    return conn


def _build_dataplane(data_dir: Path, rows: list[str]):
    """Real DataplaneSource: raw pipe rows → rebuild() → genuine v4+v6 shards."""
    from ipdb._sources.dataplane import DataplaneSource
    src = DataplaneSource(data_dir)
    (data_dir / "dataplane.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")
    src.rebuild()
    return src


def _build_turris(data_dir: Path, rows: list[str]):
    """Real TurrisGreylistSource: CSV rows (Address,Tags) → genuine shards."""
    from ipdb._sources.turris_greylist import TurrisGreylistSource
    src = TurrisGreylistSource(data_dir)
    lines = ["Address,Tags"] + rows
    (data_dir / "turris_greylist.csv").write_text("\n".join(lines) + "\n",
                                                  encoding="utf-8")
    src.rebuild()
    return src


def _units_rows(conn: sqlite3.Connection) -> dict:
    return {r[0]: tuple(r[1:]) for r in conn.execute(
        "SELECT ip, is_v6, is_cidr, last_seen, has_first_seen FROM units")}


def test_walk_v4_v6_cidr_merge_and_stats(data_dir, db, monkeypatch):
    dp = _build_dataplane(data_dir, [
        "1513399|TEST AS|203.0.113.5|2026-10-01T00:00:00Z|sshpwauth",
        "1513399|TEST AS|203.0.113.99|2026-10-02T00:00:00Z|dnsrd",
        # same /32 twice, different evidence → one record, evidence LIST,
        # per-unit last_seen must take the max across the list
        "1513399|TEST AS|203.0.113.7|2026-09-25T00:00:00Z|sshpwauth",
        "1513399|TEST AS|203.0.113.7|2026-10-05T00:00:00Z|dnsrd",
        "64512|V6 AS|2001:db8::1|2026-10-03T00:00:00Z|telnetlogin",
    ])
    tg = _build_turris(data_dir, [
        "203.0.113.5,ftp/http",            # cross-source duplicate of dp row
        "198.51.100.0/24,smtp",            # v4 CIDR unit
        "2001:db8:aaaa::/48,telnet",       # v6 CIDR unit
    ])
    monkeypatch.setattr(universe_walk, "_threat_sources", lambda: [dp, tg])

    stats = universe_walk.walk_universe(data_dir, db,
                                        engine_path=ENGINE_BACKEND)

    rows = _units_rows(db)
    # /32 and /128 units are written as plain IP text (no /32 suffix)
    assert rows["203.0.113.5"] == (0, 0, "2026-10-01T00:00:00Z", 1)
    assert rows["203.0.113.99"] == (0, 0, "2026-10-02T00:00:00Z", 1)
    # evidence list on one record: last_seen = max, first_seen present
    assert rows["203.0.113.7"] == (0, 0, "2026-10-05T00:00:00Z", 1)
    # v6 /128 → plain compressed v6 text
    assert rows["2001:db8::1"] == (1, 0, "2026-10-03T00:00:00Z", 1)
    # CIDR units keep CIDR text (v6 compressed); turris rows carry no
    # last_seen/first_seen → NULL / 0
    assert rows["198.51.100.0/24"] == (0, 1, None, 0)
    assert rows["2001:db8:aaaa::/48"] == (1, 1, None, 0)
    # cross-source merge: turris re-insert of 203.0.113.5 must NOT clobber
    # dataplane's last_seen/has_first_seen (max / OR merge, not overwrite)
    assert len(rows) == 6

    assert stats["units_total"] == 6
    assert stats["units_v4"] == 4
    assert stats["units_v6"] == 2
    assert stats["cidr_units"] == 2
    assert stats["per_source"] == {"dataplane": 4, "turris_greylist": 3}
    assert stats["first_seen_coverage"] == 4 / 6
    assert stats["skipped_anomalies"] == 0


def test_walk_skips_misaligned_range_anomaly(data_dir, db, monkeypatch):
    """Hand-built shard (inline-dict evidence, no payloads sub-db): a
    misaligned [start, end] range summarizes to >1 network → anomaly skip;
    the aligned /32 sibling record survives."""
    import lmdb
    from ipdb._sources._lmdb import encode_key, encode_value

    class StubFeed:
        name = "stubfeed"
        category = "threat"
        classification_type = "scanner"

        def __init__(self, d: Path):
            self._lmdb_base = d / "stubfeed.txt.lmdb"
            self._lmdb6_base = d / "stubfeed.txt.v6.lmdb"   # no ptr → skipped

    stub = StubFeed(data_dir)
    base = stub._lmdb_base
    env = lmdb.open(str(base.parent / f"{base.name}.1"), subdir=True,
                    map_size=1 << 20, max_dbs=2)
    ev = {"classification_type": "scanner", "verdict": "malicious"}
    with env.begin(write=True) as txn:
        txn.put(encode_key(int(ipaddress.IPv4Address("10.0.0.1"))),
                encode_value(int(ipaddress.IPv4Address("10.0.0.5")),
                             {**ev, "last_seen": "2026-10-01T00:00:00Z"}))
        txn.put(encode_key(int(ipaddress.IPv4Address("192.0.2.7"))),
                encode_value(int(ipaddress.IPv4Address("192.0.2.7")), ev))
    env.sync(True)
    env.close()
    (base.parent / (base.name + ".ptr")).write_text("1\n", encoding="utf-8")

    monkeypatch.setattr(universe_walk, "_threat_sources", lambda: [stub])
    stats = universe_walk.walk_universe(data_dir, db,
                                        engine_path=ENGINE_BACKEND)

    assert stats["skipped_anomalies"] == 1
    assert stats["units_total"] == 1
    assert _units_rows(db) == {"192.0.2.7": (0, 0, None, 0)}


def test_walk_no_shard_and_empty_universe(data_dir, db, monkeypatch):
    """No ptr files at all → families skipped silently; empty universe still
    yields a full stats dict (coverage 0.0, no division by zero)."""

    class Ghost:
        name = "ghost"
        category = "threat"
        classification_type = "scanner"

        def __init__(self, d: Path):
            self._lmdb_base = d / "ghost.txt.lmdb"
            self._lmdb6_base = d / "ghost.txt.v6.lmdb"

    monkeypatch.setattr(universe_walk, "_threat_sources",
                        lambda: [Ghost(data_dir)])
    stats = universe_walk.walk_universe(data_dir, db,
                                        engine_path=ENGINE_BACKEND)
    assert stats == {"units_total": 0, "units_v4": 0, "units_v6": 0,
                     "cidr_units": 0, "per_source": {},
                     "first_seen_coverage": 0.0, "skipped_anomalies": 0}


def test_is_threat_source_filter():
    class Threat:
        name, category, classification_type = "t", "threat", "scanner"

    class Sentinel:                      # internal canary shape: excluded
        name, category = "sentinel", "threat"
        internal = True

    class Geo:                           # non-threat: excluded
        name, category = "geo", "geo_asn"
        classification_type = "scanner"  # even if it somehow carried one

    assert universe_walk._is_threat_source(Threat())
    assert not universe_walk._is_threat_source(Sentinel())
    assert not universe_walk._is_threat_source(Geo())
    assert not universe_walk._is_threat_source(object())   # no attrs at all
