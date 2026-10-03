"""Task 4 tests — CLI orchestration: real subprocess end-to-end + failure path.

Fixture strategy = T1's real-shard 手法 + T2's real-protocol stub 手法:

* engine shard: DataplaneSource / TurrisGreylistSource fed hand-written raw
  files, then ``rebuild()`` → genuine epoch/ptr LMDB shards under a tmp data
  dir. The CLI subprocess discovers them through the REAL ``ipdb`` registry
  (no seam — unlike T1's unit tests nothing is monkeypatched across the
  process boundary; every source without a shard is skipped silently).
* stub API: stdlib ThreadingHTTPServer speaking the pinned NDJSON protocol
  (start → row{idx,result} → progress → done), rows emitted out of order.
* SUT: ``sys.executable scripts/generate_blocklist.py`` as a real subprocess
  → exit code, stdout manifest, stderr progress lines, on-disk artifacts are
  all observed from outside, exactly as cron/systemd would see them.

Universe (7 units, shaped): 4 v4 /32 + 1 v6 /128 (dataplane raw) + 1 v4 CIDR
+ 1 v6 CIDR (turris csv) → stub verdicts: 4 malicious (including the v6 line
and the v4-CIDR line that must surface in every tier), 1 suspicious, 2
benign — none of the latter may appear in any artifact.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI = REPO_ROOT / "scripts" / "generate_blocklist.py"
ENGINE_BACKEND = Path("/home/huxiao/dev/pi-ip-lookup-tool/backend")

DEFAULT_TIERS = (100, 500, 1000, 5000, 10000)
EXPECTED_ARTIFACTS = {f"top_{n}.{ext}" for n in DEFAULT_TIERS
                      for ext in ("txt", "csv")} | {"manifest.json"}

# 排序全链端到端期望:sc=3 > sc=2 > (sc=1, conf 同分 60:last_seen
# 非 NULL 在前、turris CIDR 的 NULL LAST 殿后)
EXPECTED_ORDER = ["203.0.113.7", "203.0.113.5",
                  "2001:db8::1", "198.51.100.0/24"]

DATA_PLANE_ROWS = [
    "1513399|TEST AS|203.0.113.7|2026-10-05T00:00:00Z|sshpwauth",
    "1513399|TEST AS|203.0.113.5|2026-10-01T00:00:00Z|sshpwauth",
    "1513399|TEST AS|198.51.100.5|2026-10-02T00:00:00Z|dnsrd",   # suspicious
    "64512|RES AS|192.0.2.1|2026-10-02T00:00:00Z|any",           # benign
    "64512|V6 AS|2001:db8::1|2026-10-03T00:00:00Z|telnetlogin",  # malicious v6
]
TURRIS_ROWS = ["198.51.100.0/24,smtp",       # malicious v4 CIDR
               "2001:db8:aaaa::/48,telnet"]  # benign v6 CIDR


# ── T1 手法:real source classes + raw file + rebuild() → 真分片 ──

def _build_engine_shards(data_dir: Path) -> None:
    from ipdb._sources.dataplane import DataplaneSource
    from ipdb._sources.turris_greylist import TurrisGreylistSource
    (data_dir / "dataplane.txt").write_text(
        "\n".join(DATA_PLANE_ROWS) + "\n", encoding="utf-8")
    DataplaneSource(data_dir).rebuild()
    (data_dir / "turris_greylist.csv").write_text(
        "Address,Tags\n" + "\n".join(TURRIS_ROWS) + "\n", encoding="utf-8")
    TurrisGreylistSource(data_dir).rebuild()


@pytest.fixture
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    _build_engine_shards(d)
    return d


# ── T2 手法:threaded stdlib stub speaking the pinned NDJSON protocol ──

def _merge(value):
    return {"value": value, "confidence": 90, "algorithm": "voting",
            "sources": [{"source": "geo", "value": value,
                         "reliability": 1.0, "authoritative": True}]}


def _cls(type_, sources):
    return {"type": type_, "verdict": "malicious", "detected": True,
            "confidence": 80, "sources": [{"source": s, "value": True,
                                           "reliability": 0.9} for s in sources]}


def _row(ip, verdict, confidence, classifications=None, is_reserved=False):
    return {"ip": ip, "country": _merge("US"), "asn": _merge("64512"),
            "threat": {"verdict": verdict, "confidence": confidence,
                       "types": [], "is_cdn": False},
            "classifications": classifications or {}, "attributes": {},
            "is_reserved": is_reserved}


# 键 = 锚点形态(CIDR 单元剥前缀后引擎实际收到的东西)
STUB_RESULTS = {
    "203.0.113.7": _row("203.0.113.7", "malicious", 87, classifications={
        "scanner": _cls("scanner", ["dataplane", "turris_greylist"]),
        "spam": _cls("spam", ["dataplane", "blocklist_de"])}),
    "203.0.113.5": _row("203.0.113.5", "malicious", 75, classifications={
        "scanner": _cls("scanner", ["dataplane", "turris_greylist"])}),
    "198.51.100.5": _row("198.51.100.5", "suspicious", 40, classifications={
        "scanner": _cls("scanner", ["dataplane"])}),
    "192.0.2.1": _row("192.0.2.1", "benign", 0, is_reserved=True),
    "2001:db8::1": _row("2001:db8::1", "malicious", 60, classifications={
        "bruteforce": _cls("bruteforce", ["dataplane"])}),
    "198.51.100.0": _row("198.51.100.0", "malicious", 60, classifications={
        "spam": _cls("spam", ["turris_greylist"])}),
    "2001:db8:aaaa::": _row("2001:db8:aaaa::", "benign", 0),
}


def _ok_responder(attempt_no, ips, headers):
    events = [{"type": "start", "total": len(ips)}]
    for idx in reversed(range(len(ips))):      # 乱序行,逼真协议
        events.append({"type": "row", "idx": idx,
                       "result": STUB_RESULTS[ips[idx]]})
    events.append({"type": "progress", "done": len(ips), "total": len(ips)})
    events.append({"type": "done", "invalid_lines": 0, "ipv6_unsupported": 0})
    payload = ("".join(json.dumps(e) + "\n" for e in events)).encode("utf-8")
    return 200, "application/x-ndjson", payload


class _Stub:
    """responder(attempt_no, ips, headers) -> (status, ctype, payload)."""

    def __init__(self, responder):
        self.requests: list[list[str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(
                    int(self.headers.get("Content-Length", 0)))
                ips = json.loads(body).get("ips", [])
                outer.requests.append(ips)
                status, ctype, payload = responder(
                    len(outer.requests), ips, self.headers)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
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


# ── CLI 子进程(真实 sys.executable,环境不泄漏 IP_RADAR_DATA_DIR)──

def _run_cli(*flags: str, timeout: int = 120) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "IP_RADAR_DATA_DIR"}
    return subprocess.run(
        [sys.executable, str(CLI), *map(str, flags)],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env,
        timeout=timeout)


# ── 成功路径:全管线一次真跑 ──

def test_cli_end_to_end_publishes_tiers_and_merged_manifest(
        data_dir, stub, tmp_path):
    out_dir = tmp_path / "out"
    s = stub(_ok_responder)

    proc = _run_cli("--engine-path", ENGINE_BACKEND, "--data-dir", data_dir,
                    "--api-base", s.base, "--out-dir", out_dir)

    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
    # 每阶段恰好一行带计数的进度(stderr;stdout 只允许 manifest JSON)
    for stage in ("[walk]", "[enrich]", "[emit]"):
        assert stage in proc.stderr
    manifest = json.loads(proc.stdout)

    # 产物集恰为 10 档位文件 + manifest.json,.staging 已收尾
    assert {p.name for p in out_dir.iterdir()} == EXPECTED_ARTIFACTS
    assert not (out_dir / ".staging").exists()
    # manifest 重写走 tmp + os.replace(原子),不留 .tmp 残渣
    assert not (out_dir / "manifest.json.tmp").exists()

    # stdout manifest == 落盘 manifest;7 个 emit 必填字段 + CLI 合并 ctx
    on_disk = json.loads(
        (out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk == manifest
    assert "error" not in manifest
    for field in ("generated_at", "tiers", "universe", "malicious_pool",
                  "cidr_units", "units_v6", "first_seen_coverage",
                  "walk_stats", "enrich_stats", "elapsed_s", "peak_rss_mb",
                  "api_base"):
        assert field in manifest, field
    assert manifest["universe"] == 7
    assert manifest["malicious_pool"] == 4
    assert manifest["cidr_units"] == 1            # 198.51.100.0/24(池内)
    assert manifest["units_v6"] == 1              # 2001:db8::1(池内)
    assert manifest["first_seen_coverage"] == pytest.approx(3 / 4)
    assert manifest["tiers"] == {str(n): 4 for n in DEFAULT_TIERS}
    assert manifest["walk_stats"]["units_total"] == 7
    assert manifest["walk_stats"]["units_v6"] == 2
    assert manifest["walk_stats"]["cidr_units"] == 2
    assert manifest["walk_stats"]["per_source"] == {
        "dataplane": 5, "turris_greylist": 2}
    assert manifest["enrich_stats"]["queried"] == 7
    assert manifest["enrich_stats"]["malicious"] == 4
    assert manifest["enrich_stats"]["requests"] == 1
    assert manifest["api_base"] == s.base
    assert manifest["elapsed_s"] > 0
    assert manifest["peak_rss_mb"] > 0

    # 单次整批请求(7 单位 < chunk 500),锚点形态(CIDR 剥前缀、v6 原样);
    # 批内顺序是 LMDB 键序(游标枚举),契约只钉集合不钉顺序
    assert len(s.requests) == 1
    assert sorted(s.requests[0]) == sorted([
        "203.0.113.7", "203.0.113.5", "198.51.100.5", "192.0.2.1",
        "2001:db8::1", "198.51.100.0", "2001:db8:aaaa::"])

    # 字节级钉死排序全链 + CIDR 行与 v6 行在产物里 + up to N(池 4)
    expected_txt = ("\n".join(EXPECTED_ORDER) + "\n").encode("utf-8")
    for n in DEFAULT_TIERS:
        assert (out_dir / f"top_{n}.txt").read_bytes() == expected_txt
    raw_csv = (out_dir / "top_100.csv").read_bytes()
    assert raw_csv.split(b"\n")[0] == (b"ip,asn,country,classes,confidence,"
                                       b"source_count,sources,last_seen")
    # CIDR 行写单元原文(锚点二象性),turris 无 last_seen → 空
    assert ('198.51.100.0/24,64512,US,spam,60,1,turris_greylist,'
            in (out_dir / "top_100.csv").read_text(encoding="utf-8"))
    assert "2001:db8::1,64512,US,bruteforce,60,1,dataplane,2026-10-03T00:00:00Z" \
        in (out_dir / "top_100.csv").read_text(encoding="utf-8")

    # suspicious / benign 单元绝不出现在任何产物
    for name in EXPECTED_ARTIFACTS - {"manifest.json"}:
        body = (out_dir / name).read_text(encoding="utf-8")
        for absent in ("198.51.100.5", "192.0.2.1", "2001:db8:aaaa::/48"):
            assert absent not in body, (name, absent)


def test_cli_local_anchor_data_dir_flag_drives_registry(data_dir, stub,
                                                       tmp_path):
    """--data-dir 旗标是引擎 registry 的唯一数据来源:父进程即便泄漏了
    别的 IP_RADAR_DATA_DIR,子进程也按旗标走(7 单位宇宙,而非别的)。"""
    out_dir = tmp_path / "out2"
    s = stub(_ok_responder)
    env = {**os.environ, "IP_RADAR_DATA_DIR": "/nonexistent-data-dir"}
    proc = subprocess.run(
        [sys.executable, str(CLI), "--engine-path", str(ENGINE_BACKEND),
         "--data-dir", str(data_dir), "--api-base", s.base,
         "--out-dir", str(out_dir)],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=120)
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
    assert json.loads(proc.stdout)["walk_stats"]["units_total"] == 7


# ── 失败路径:引擎恒 500 → 重试耗尽 → error manifest,无半成品 ──

def test_cli_engine_always_500_writes_error_manifest_nothing_published(
        data_dir, stub, tmp_path):
    out_dir = tmp_path / "out"

    def always_500(attempt_no, ips, headers):
        return 500, "application/json", json.dumps(
            {"error": {"code": "internal",
                       "message": "engine on fire"}}).encode("utf-8")

    s = stub(always_500)
    proc = _run_cli("--engine-path", ENGINE_BACKEND, "--data-dir", data_dir,
                    "--api-base", s.base, "--out-dir", out_dir, timeout=180)

    assert proc.returncode == 1
    # 初次 + 3 次退避重试 = 4 次尝试(真实 2/4/8s 退避在跑)
    assert len(s.requests) == 4
    # 首跑无产物:out_dir 只有 error manifest,stdout 不打印成功 JSON
    assert [p.name for p in out_dir.iterdir()] == ["manifest.json"]
    # error manifest 同样原子换入,无 .tmp 残渣
    assert not (out_dir / "manifest.json.tmp").exists()
    payload = json.loads(
        (out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "engine on fire" in payload["error"]
    assert "enrich" in payload["error"]              # 失败阶段可辨认
    assert payload["walk_stats"]["units_total"] == 7  # 部分统计透传
    assert "error" in proc.stderr                     # error manifest → stderr
    assert proc.stdout == ""
