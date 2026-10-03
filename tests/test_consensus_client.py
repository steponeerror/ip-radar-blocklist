"""Task 2 tests — consensus_client: chunked stream-API enrichment of units.

Stub strategy (Step 1-pinned engine protocol, backend/main.py query_ips_stream
→ _stream_lookup): stdlib ThreadingHTTPServer replays canned NDJSON events —
start{total} → row{idx,result}×N (out of input order on purpose) →
progress{done,total} → done{invalid_lines,ipv6_unsupported}; a failure done
carries error+code. Pure-stdlib module under test: no engine import here.

Retry semantics (supervisor ruling on plan text 「3 次指数退避重试」):
initial attempt + 3 retries = 4 attempts total, backoffs 2/4/8s; requests
stat counts ALL HTTP attempts, retries counts attempts beyond the first.
"""
import json
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REPO_ROOT = "/home/huxiao/dev/ip-radar-blocklist-pipeline"
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts import consensus_client as cc  # noqa: E402

# 全列建表(caller 先 ALTER 的形态,测试按 Global Constraints 全列自建)
UNITS_DDL = """
CREATE TABLE units(
    ip TEXT PRIMARY KEY,
    is_v6 INTEGER NOT NULL,
    is_cidr INTEGER NOT NULL,
    last_seen TEXT,
    has_first_seen INTEGER NOT NULL DEFAULT 0,
    verdict TEXT, confidence INTEGER, classes TEXT, sources TEXT,
    source_count INTEGER, asn TEXT, country TEXT
)
"""

NO_BACKOFF = (0.0, 0.0, 0.0)   # test injection: real 2/4/8s is nightly-grade


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

    # demo-mode 守卫头 + UA 逐请求都在
    for h in s.log_headers:
        assert h.get("x-ipradar-client") == "web"
        assert h.get("user-agent") == "ipradar-blocklist-exporter/1.0"
        assert h.get("content-type") == "application/json"
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
                          "elapsed_s"}
    assert stats["queried"] == 4
    assert stats["malicious"] == 2
    assert stats["requests"] == 1
    assert stats["retries"] == 0
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


def test_memory_budget_exceeded_after_chunk(db, stub, monkeypatch):
    monkeypatch.setattr(cc, "_current_rss_mb", lambda: 999.0)
    _add_units(db, "203.0.113.7", "198.51.100.5", "192.0.2.1", "2001:db8::1")

    def responder(attempt_no, ips, headers):
        events = [_start(ips)]
        events += [_row_evt(i, _row(ip, "benign", 0))
                   for i, ip in enumerate(ips)]
        events.append(_done_ok())
        return 200, "application/x-ndjson", _ndjson(*events)

    s = stub(responder)
    with pytest.raises(cc.MemoryBudgetExceeded, match="140"):
        cc.enrich_with_consensus(db, s.base, chunk=2, max_rss_mb=140)
    # 第一块已提交,第二块未发 —— 爆顶即停,不多发一个请求
    rows = _units_by_ip(db)
    assert rows["203.0.113.7"][0] == "benign"
    assert rows["198.51.100.5"][0] == "benign"
    assert rows["192.0.2.1"][0] is None
    assert len(s.log_bodies) == 1


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
                     "retries": 0, "elapsed_s": stats["elapsed_s"]}
    assert s.log_bodies == []
