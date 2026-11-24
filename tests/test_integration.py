"""#444 B 步集成测试 —— CLI 全管线(scan → geo → emit)。

夹具(conftest):三个真源类(dataplane / turris_greylist 威胁类 +
danmeuk_tor 资产类)在临时目录写原始文件 + rebuild() → 正版纪元/ptr
LMDB 分片;夹具里有多源同一地址(1.2.3.5)、资产类证人、保留地址单元
(10.99.99.1)、v4/v6 网段单元(5.6.7.0/24、2a00:1450:4001::/48)、
只有资产类记录的地址(1.2.3.99,不产单元)。

不再有 HTTP 桩(逐 IP 查询路径随 #444 删除,规格 Q2 不留回退):判定
一致性改由「扫描入库值 vs 同进程 lookup()」对拍直接钉死(用例 2)。
子进程用例(sys.executable scripts/generate_blocklist.py)从外面观察
退出码、stdout/stderr、落盘产物 —— cron/systemd 看到什么就测什么。
"""
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import scan_units as su                  # noqa: E402
from scripts import generate_blocklist as gb          # noqa: E402

from conftest import (ASOF, ENGINE_BACKEND, MALICIOUS_TOTAL,  # noqa: E402
                      SINGLE_MALICIOUS_POOL, TURRIS_ROWS, UNIVERSE_TOTAL,
                      create_units)

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI = REPO_ROOT / "scripts" / "generate_blocklist.py"

DEFAULT_TIERS = (100, 500, 1000, 5000, 10000)
EXPECTED_ARTIFACTS = {f"top_{n}.{ext}" for n in DEFAULT_TIERS
                      for ext in ("txt", "csv")} | {"manifest.json"}

# 排序全链端到端期望:sc=2 组内(5.6.7.9 与 1.2.3.5)confidence 并列,
# last_seen DESC 定序;sc=1 组(1.2.3.7 与 2606:4700::1)同理
EXPECTED_ORDER = ["5.6.7.9", "1.2.3.5", "1.2.3.7", "2606:4700::1"]

# 字节级钉死排序全链 + geo 补查回写(asn 胜者来自 dataplane;country 无
# 地理源 → 引擎兜底值 N/A)+ 提取规则(只有 malicious 分类计数)
EXPECTED_CSV_ROWS = [
    "5.6.7.9,1513399,N/A,scanner,78,2,"
    "2026-10-02T00:00:00Z,2026-10-02T00:00:00Z",
    "1.2.3.5,1513399,N/A,brute-force;scanner,70,2,"
    "2026-10-01T00:00:00Z,2026-10-01T00:00:00Z",
    "1.2.3.7,1513399,N/A,brute-force,70,1,"
    "2026-10-05T00:00:00Z,2026-10-05T00:00:00Z",
    "2606:4700::1,64512,N/A,brute-force,70,1,"
    "2026-10-03T00:00:00Z,2026-10-03T00:00:00Z",
]


def _run_cli(*flags: str, timeout: int = 180) -> subprocess.CompletedProcess:
    # 真实 sys.executable;环境不泄漏 IP_RADAR_DATA_DIR(旗标即真相)
    env = {k: v for k, v in os.environ.items()
           if k not in ("IP_RADAR_DATA_DIR", "IPRADAR_API_KEY")}
    return subprocess.run(
        [sys.executable, str(CLI), *map(str, flags)],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env,
        timeout=timeout)


# ── 用例 1:CLI 真子进程端到端 ──

def test_cli_end_to_end_publishes_tiers_and_manifest(engine_env, tmp_path):
    out_dir = tmp_path / "out"
    proc = _run_cli("--engine-path", ENGINE_BACKEND,
                    "--data-dir", engine_env["data_dir"],
                    "--out-dir", out_dir, "--asof", str(int(ASOF)))

    assert proc.returncode == 0, f"stderr:\n{proc.stderr[-4000:]}"
    # 每阶段恰好一行带计数的进度(stderr;stdout 只允许 manifest JSON)
    for stage in ("[scan]", "[geo]", "[emit]"):
        assert stage in proc.stderr
    manifest = json.loads(proc.stdout)

    # 产物集恰为 10 档位文件 + manifest.json,.staging 已收尾
    assert {p.name for p in out_dir.iterdir()} == EXPECTED_ARTIFACTS
    assert not (out_dir / ".staging").exists()
    # manifest 重写走 tmp + os.replace(原子),不留 .tmp 残渣
    assert not (out_dir / "manifest.json.tmp").exists()

    # stdout manifest == 落盘 manifest;emit 必填字段 + CLI 合并的新字段
    on_disk = json.loads(
        (out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk == manifest
    assert "error" not in manifest
    for field in ("generated_at", "tiers", "universe", "malicious_pool",
                  "malicious_single_ip", "cidr_units", "units_v6",
                  "first_seen_coverage",
                  "asof", "epochs", "scan_stats", "geo_stats",
                  "stage_elapsed_s", "elapsed_s", "peak_rss_mb",
                  "peak_rss_anon_mb"):
        assert field in manifest, field
    # 开跑时刻钉死:--asof 原样进清单
    assert manifest["asof"] == ASOF
    assert manifest["universe"] == UNIVERSE_TOTAL
    assert manifest["malicious_pool"] == MALICIOUS_TOTAL
    assert manifest["malicious_single_ip"] == SINGLE_MALICIOUS_POOL
    assert manifest["cidr_units"] == 2            # 5.6.7.0/24、2a00:...::/48
    assert manifest["units_v6"] == 2              # v6 恶意池(单 + 网段)
    assert manifest["tiers"] == {str(n): SINGLE_MALICIOUS_POOL
                                 for n in DEFAULT_TIERS}

    # scan_stats:单元数(v4/v6/单地址/网段)、扫描器自报分解、恶意数、
    # 读了几条记录、判定时刻
    scan_stats = manifest["scan_stats"]
    assert scan_stats["units_total"] == UNIVERSE_TOTAL
    assert scan_stats["units_v4"] == 5
    assert scan_stats["units_v6"] == 2
    assert scan_stats["units_single"] == 5
    assert scan_stats["units_cidr"] == 2
    assert scan_stats["scanner_units"] == {"v4_single": 4, "v4_cidr": 1,
                                           "v6_single": 1, "v6_cidr": 1}
    assert scan_stats["malicious"] == MALICIOUS_TOTAL
    assert scan_stats["records_total"] == 10
    assert scan_stats["skipped_anomalies"] == 0
    assert scan_stats["asof"] == ASOF
    # geo 核对里与「扫描之后有源被重建」有关的三项(#444 生产试跑
    # 2026-11-25):
    # 本夹具扫描之后没有源重建 → 没有被跳过的地址
    assert manifest["geo_stats"]["changed_sources"] == []
    assert manifest["geo_stats"]["drift_skipped"] == 0
    assert manifest["geo_stats"]["verified"] == \
        manifest["geo_stats"]["looked_up"] == SINGLE_MALICIOUS_POOL

    # 各库纪元号进清单(扫描器逐源报 [v4, v6];无分片的源是
    # [None, None],照实透传 —— 夹具在子进程里经真 registry 发现,只有
    # 三个夹具源有库,纪元都是 1)
    assert manifest["epochs"]["dataplane"] == [1, 1]
    assert manifest["epochs"]["turris_greylist"] == [1, 1]
    assert manifest["epochs"]["danmeuk_tor"] == [1, 1]
    assert manifest["epochs"] == scan_stats["epochs"]

    # geo_stats:进榜单 IP 全量补查
    assert manifest["geo_stats"]["looked_up"] == SINGLE_MALICIOUS_POOL
    # geo 阶段自己也量匿名内存(load_db 之后和补查途中各采;#444 评审
    # P2-3):容器的 150MB 上限原先在这一段没有读数
    assert manifest["geo_stats"]["peak_rss_anon_mb"] > 0
    # 清单里的峰值是四舍五入到 0.1 的(18.113 → 18.1),比的时候同样取一位
    assert manifest["peak_rss_anon_mb"] >= \
        round(manifest["geo_stats"]["peak_rss_anon_mb"], 1)
    for key in ("scan", "geo", "emit"):
        assert manifest["stage_elapsed_s"][key] > 0
    assert manifest["elapsed_s"] > 0
    assert manifest["peak_rss_mb"] > 0
    assert manifest["peak_rss_anon_mb"] > 0

    # 字节级钉死排序全链 + 档位无 CIDR 行 + 嵌套档位是超集(up to N,池 4)
    expected_txt = ("\n".join(EXPECTED_ORDER) + "\n").encode("utf-8")
    tier_sets = []
    for n in DEFAULT_TIERS:
        txt = (out_dir / f"top_{n}.txt").read_bytes()
        assert txt == expected_txt
        assert b"/" not in txt                    # 档位里没有 CIDR 行
        tier_sets.append(set(txt.decode().split()))
    assert (tier_sets[0] <= tier_sets[1] <= tier_sets[2]
            <= tier_sets[3] <= tier_sets[4])
    csv_lines = (out_dir / "top_100.csv").read_text(
        encoding="utf-8").splitlines()
    assert csv_lines[0] == ("ip,asn,country,classes,confidence,"
                            "source_count,first_seen,last_seen")
    assert csv_lines[1:] == EXPECTED_CSV_ROWS

    # 保留地址单元 / 资产only 地址 / 网段单元文本绝不出现在任何产物
    for name in EXPECTED_ARTIFACTS - {"manifest.json"}:
        body = (out_dir / name).read_text(encoding="utf-8")
        for absent in ("10.99.99.1", "1.2.3.99",
                       "5.6.7.0/24", "2a00:1450:4001::/48"):
            assert absent not in body, (name, absent)


def test_cli_local_anchor_data_dir_flag_drives_registry(engine_env, tmp_path):
    """--data-dir 旗标是引擎 registry 的唯一数据来源:父进程即便泄漏了
    别的 IP_RADAR_DATA_DIR,子进程也按旗标走(7 单元宇宙,而非别的)。"""
    out_dir = tmp_path / "out2"
    env = {k: v for k, v in os.environ.items()
           if k not in ("IP_RADAR_DATA_DIR", "IPRADAR_API_KEY")}
    env["IP_RADAR_DATA_DIR"] = "/nonexistent-data-dir"
    proc = subprocess.run(
        [sys.executable, str(CLI), "--engine-path", str(ENGINE_BACKEND),
         "--data-dir", str(engine_env["data_dir"]),
         "--out-dir", str(out_dir), "--asof", str(int(ASOF))],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=180)
    assert proc.returncode == 0, f"stderr:\n{proc.stderr[-4000:]}"
    assert json.loads(proc.stdout)["scan_stats"]["units_total"] == \
        UNIVERSE_TOTAL


# ── 用例 2:对拍(扫描入库值 vs 同进程 lookup)──

def test_scan_rows_match_inprocess_lookup(engine_env, monkeypatch):
    """夹具数据目录上,units 表每一行的五列与同进程
    lookup(网络地址, asof=同一时刻).to_dict() 经 extract_fields 算出的
    一样;行数等于扫描器的单元数。"""
    db = sqlite3.connect(":memory:")
    create_units(db)
    stats = su.scan_units(engine_env["data_dir"], db, asof=ASOF)

    # 扫描句柄已关,同进程才能 load_db(py-lmdb 同路径禁双开);
    # IP_RADAR_POOL_CHILD=1 防 load_db 清旧纪元目录
    monkeypatch.setenv("IP_RADAR_POOL_CHILD", "1")
    from ipdb import load_db, lookup, _registry
    load_db()
    allowed = frozenset(s.name for s in _registry._enabled_sources()
                        if s.name not in _registry._PRIVATE)

    rows = list(db.execute(
        "SELECT ip, verdict, confidence, classes, sources, source_count"
        " FROM units"))
    assert stats["units_total"] == UNIVERSE_TOTAL
    assert stats["scanner_units"] == {"v4_single": 4, "v4_cidr": 1,
                                      "v6_single": 1, "v6_cidr": 1}
    assert len(rows) == sum(stats["scanner_units"].values())
    for ip, *stored in rows:
        addr = ip.partition("/")[0]     # 网段单元在网络地址上判定
        r = lookup(addr, allowed_sources=allowed, asof=ASOF).to_dict()
        assert tuple(stored) == tuple(su.extract_fields(r)[:5]), ip

    # 保留地址行:单元产出、判定 benign、数值列 NULL;资产only 地址不产单元
    assert db.execute("SELECT verdict, confidence FROM units"
                      " WHERE ip = '10.99.99.1'").fetchone() == ("benign", None)
    assert db.execute("SELECT COUNT(*) FROM units WHERE ip = '1.2.3.99'"
                      ).fetchone()[0] == 0


# ── 用例 3:判定对不上就停(直接调 geo 函数)──

def test_geo_verdict_mismatch_aborts(engine_env):
    """表里某一行的 confidence 改掉再跑 geo 阶段 → 抛错,错误信息里有
    那个 IP 和列名。"""
    db = sqlite3.connect(":memory:")
    create_units(db)
    su.scan_units(engine_env["data_dir"], db, asof=ASOF)
    db.execute("UPDATE units SET confidence = confidence + 1"
               " WHERE ip = '1.2.3.5'")

    with pytest.raises(gb.GeoMismatchError,
                       match=r"1\.2\.3\.5.*confidence"):
        gb._geo_fill_and_verify(db, asof=ASOF)


# ── 用例 3 延伸:扫描之后有源被重建(生产试跑 2026-11-25 的失败形)──
#
# 生产上扫描要跑一个多小时,期间引擎照常重建源(新纪元目录 + 换 ptr)。
# 扫描读的是开跑时钉住的旧纪元;geo 核对调的 lookup() 读的是现在的纪元。
# 重建恰好改了某个进榜地址的证据时,两边五列必不一致 —— 这不是扫描器
# 的错。规则:证据里含「扫描之后被重建过的源」的地址,只核对没重建的
# 那部分源(把重建过的源从两边都去掉再比);其余地址照常逐列核对。

TURRIS_EXTRA_ROW = "1.2.3.7,smtp"       # 让 1.2.3.7 多出一个源(turris)


def _scan_then_rebuild_turris(engine_env):
    """扫描入库 → 重建 turris(多一行)→ 返回 (db, 扫描时钉住的 epochs)。
    1.2.3.7 扫描时只有 dataplane;重建后查询接口看到 dataplane + turris。"""
    db = sqlite3.connect(":memory:")
    create_units(db)
    stats = su.scan_units(engine_env["data_dir"], db, asof=ASOF)
    data_dir = engine_env["data_dir"]
    (data_dir / "turris_greylist.csv").write_text(
        "Address,Tags\n" + "\n".join(TURRIS_ROWS + [TURRIS_EXTRA_ROW])
        + "\n", encoding="utf-8")
    turris = engine_env["insts"][1]
    turris.rebuild()
    turris._reader = None
    turris._reader6 = None
    return db, stats["epochs"]


def test_geo_source_rebuilt_after_scan_is_skipped_not_fatal(engine_env):
    """扫描之后 turris 被重建、多给了 1.2.3.7 一条记录 → 那个地址五列
    对不上,但只差在重建过的源上:不中止;清单报出重建过的源、跳过的
    地址数和例子;进榜地址全部补查过。"""
    db, epochs = _scan_then_rebuild_turris(engine_env)
    before = db.execute("SELECT sources FROM units WHERE ip = '1.2.3.7'"
                        ).fetchone()[0]
    assert before == "dataplane"                   # 扫描入库值是旧纪元的

    geo = gb._geo_fill_and_verify(db, asof=ASOF, epochs=epochs)

    assert geo["changed_sources"] == ["turris_greylist"]
    assert geo["drift_skipped"] == 1
    assert geo["verified"] == geo["looked_up"] - 1 == SINGLE_MALICIOUS_POOL - 1
    assert any(ex.startswith("1.2.3.7:") and "sources" in ex
               for ex in geo["drift_examples"])
    # 入库值不因跳过而改写(档位仍按扫描时的快照出)
    assert db.execute("SELECT sources FROM units WHERE ip = '1.2.3.7'"
                      ).fetchone()[0] == "dataplane"


def test_geo_skips_only_mismatches_that_involve_a_rebuilt_source(engine_env):
    """对不上的地址,证据里没有重建过的源 → 照旧中止(别的源被重建不是
    放行理由)。这里不真重建,只在传给核对的纪元表里说 danmeuk_tor 被
    重建过(它不在 1.2.3.7 的证据里)。"""
    db = sqlite3.connect(":memory:")
    create_units(db)
    stats = su.scan_units(engine_env["data_dir"], db, asof=ASOF)
    db.execute("UPDATE units SET confidence = confidence + 1"
               " WHERE ip = '1.2.3.7'")
    lying = {**stats["epochs"], "danmeuk_tor": [999, 999]}

    with pytest.raises(gb.GeoMismatchError,
                       match=r"1\.2\.3\.7.*confidence") as excinfo:
        gb._geo_fill_and_verify(db, asof=ASOF, epochs=lying)
    # 失败清单的素材:认出了哪个源被重建过,但没有地址因此被跳过
    assert excinfo.value.changed_sources == ["danmeuk_tor"]
    assert excinfo.value.drift_skipped == 0


def test_geo_skip_requires_the_unchanged_sources_to_agree(engine_env):
    """证据里有重建过的源、但没重建的那部分也对不上 → 中止。
    1.2.3.7 重建后查询接口 = dataplane + turris;把入库值改成空 →
    没重建的 dataplane 两边就不一致了。"""
    db, epochs = _scan_then_rebuild_turris(engine_env)
    db.execute("UPDATE units SET sources = '', source_count = 0,"
               " classes = '' WHERE ip = '1.2.3.7'")

    with pytest.raises(gb.GeoMismatchError,
                       match=r"1\.2\.3\.7.*sources"):
        gb._geo_fill_and_verify(db, asof=ASOF, epochs=epochs)


# ── 用例 3 补充:对不上经 CLI 失败路径 → error manifest、退出 1 ──

def test_geo_mismatch_writes_error_manifest_nothing_published(
        engine_env, tmp_path, monkeypatch, capsys):
    """geo 阶段判定对不上 → error manifest、退出 1、不发布任何档位文件。
    lookup 打桩偏移恶意分类置信度(只影响 geo 侧;扫描侧诚实入库,
    两边必不一致)。"""
    out_dir = tmp_path / "out"
    import ipdb
    real_lookup = ipdb.lookup

    def skewed(ip, *args, **kwargs):
        result = real_lookup(ip, *args, **kwargs)
        for cls in result.classifications.values():
            if cls.detected and cls.verdict == "malicious":
                cls.confidence = cls.confidence + 7
                break
        return result

    monkeypatch.setattr(ipdb, "lookup", skewed)

    rc = gb.main([
        "--engine-path", str(ENGINE_BACKEND),
        "--data-dir", str(engine_env["data_dir"]),
        "--out-dir", str(out_dir),
        "--asof", str(int(ASOF)),
    ])

    assert rc == 1
    assert [p.name for p in out_dir.iterdir()] == ["manifest.json"]
    payload = json.loads(
        (out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "confidence" in payload["error"]
    assert "1.2.3.5" in payload["error"]
    assert payload["stage"] == "geo"
    # 失败清单里带上补查进度(#444 评审 P3-7):查了几个、哪些例子不一致
    assert payload["geo_stats"]["looked_up"] >= 1
    assert "1.2.3.5" in " ".join(payload["geo_stats"]["mismatch_examples"])
    assert payload["scan_stats"]["units_total"] == UNIVERSE_TOTAL
    assert capsys.readouterr().out == ""   # 失败不往 stdout 打成功 manifest


# ── 用例 4:引擎镜像太旧 ──

def test_cli_engine_without_scan_module_fails_loud(engine_env, tmp_path):
    """引擎镜像早于 #444(fake engine 目录没有 ipdb/_scan.py)→ CLI
    退出 1、写 error manifest、不发布任何档位文件。"""
    fake = tmp_path / "fakeengine"
    (fake / "ipdb" / "_sources").mkdir(parents=True)
    (fake / "ipdb" / "__init__.py").write_text("", encoding="utf-8")
    (fake / "ipdb" / "_sources" / "__init__.py").write_text("", encoding="utf-8")
    (fake / "ipdb" / "_sources" / "_lmdb.py").write_text("", encoding="utf-8")
    out_dir = tmp_path / "out"

    proc = _run_cli("--engine-path", fake,
                    "--data-dir", engine_env["data_dir"],
                    "--out-dir", out_dir)

    assert proc.returncode == 1
    assert [p.name for p in out_dir.iterdir()] == ["manifest.json"]
    payload = json.loads(
        (out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "引擎镜像早于 #444" in payload["error"]
    assert payload["stage"] == "scan"
    assert "error" in proc.stderr
    assert proc.stdout == ""


# ── 用例 5:扫出 0 个单元不发布空档位(#444 评审 P2-1)──

def test_cli_zero_units_refuses_to_publish(tmp_path):
    """数据目录是空的(卷没挂对时就是这个样子)→ 扫描出 0 个单元 →
    退出 1、写 error manifest、不发布任何档位文件。空档位会被宿主的
    push.sh 发成 Release,下游读成「今天没有恶意 IP」,所以必须停。
    拆掉 generate_blocklist.py 里「units_total == 0」那段守卫即红。"""
    empty = tmp_path / "empty-data"
    empty.mkdir()
    out_dir = tmp_path / "out"

    proc = _run_cli("--data-dir", empty, "--out-dir", out_dir,
                    "--asof", str(int(ASOF)))

    assert proc.returncode == 1
    assert [p.name for p in out_dir.iterdir()] == ["manifest.json"]
    payload = json.loads(
        (out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "0 个单元" in payload["error"]
    assert payload["stage"] == "scan"
    assert payload["scan_stats"]["units_total"] == 0     # 空目录 = 0 单元
    assert proc.stdout == ""
