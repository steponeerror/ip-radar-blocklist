"""scan_units 单元测试(#444 B 步)—— 三块,期望值原样搬自被删模块:

* extract_fields(原 consensus_client._extract_fields):共识列提取规则
  一字不改 —— verdict=threat.verdict;只有 malicious 行填数值和列表
  (classes/sources 取「detected 且 malicious」分类的 type 与 source
  去重排序、分号连接;confidence 取这些分类置信度的最大值,不是
  threat.confidence);asn/country 取 merged 的 value,缺失留空。
* 匿名内存红线(T7 原样):自检口径 = smaps_rollup `Anonymous:` 行
  (路径常量即注入接缝),解析失败回退 ru_maxrss 并告警一次;
  scan_units 每批提交后量一次,超 max_rss_mb 抛 MemoryBudgetExceeded。
* require_scan_engine:引擎镜像早于 #444(没有 ipdb._scan)时报错话。

扫描侧没有 HTTP 桩(逐 IP 查询路径随 #444 删除):内存红线用例经
conftest 的真源夹具小库真跑 scan_units。
"""
import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))          # scripts/ as namespace pkg portion

from scripts import scan_units as su        # noqa: E402 (stdlib-only: pre-env safe)

from conftest import ASOF, create_units     # noqa: E402


# ── canned row builders:exact engine LookupResult.to_dict() shape ──
# (原样搬自 test_consensus_client.py)

def _merge(value, confidence=90):
    return {"value": value, "confidence": confidence, "algorithm": "voting",
            "sources": [{"source": "geo", "value": value,
                         "reliability": 1.0, "authoritative": True}]}


def _cls(type_, verdict, detected, sources, cls_conf=80):
    return {"type": type_, "verdict": verdict, "detected": detected,
            "confidence": cls_conf, "algorithm": "logodds",
            "corroborated": len(sources) >= 2,
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


# ── extract_fields(期望值原样)──

def test_extract_fields_malicious_multi_classification_dedup():
    """跨 classification 去重口径:两恶意 detection 共享 dataplane;
    suspicious detection 与 archive 章(detected False)都不进计数。"""
    row = _row(
        "203.0.113.7", "malicious", 80,
        classifications={
            "scanner": _cls("scanner", "malicious", True,
                            ["dataplane", "turris_greylist"]),
            "spam": _cls("spam", "malicious", True,
                         ["dataplane", "blocklistde"]),
            "c2": _cls("c2", "suspicious", True, ["shodan"]),
            "archive": _cls("archive", "malicious", False, ["misp_archive"]),
        })
    assert su.extract_fields(row) == (
        "malicious", 80, "scanner;spam",
        "blocklistde;dataplane;turris_greylist", 3, "64512", "US")


def test_extract_fields_confidence_is_max_malicious_classification():
    """confidence = 恶意分类置信度的最大值,不是 threat.confidence
    (旧注:threat.confidence 多分类时按字典序碰运气,非确定 —— 不用)。"""
    row = _row(
        "203.0.113.7", "malicious", 87,
        classifications={
            "scanner": _cls("scanner", "malicious", True, ["dataplane"],
                            cls_conf=80),
            "spam": _cls("spam", "malicious", True, ["blocklistde"],
                         cls_conf=60),
        })
    assert su.extract_fields(row)[1] == 80


def test_extract_fields_missing_asn_value_is_empty_string():
    """缺失 MergedField value → ""(裁决:缺失留空,非 NULL)。"""
    row = _row(
        "203.0.113.0", "malicious", 60,
        classifications={"scanner": _cls("scanner", "malicious", True,
                                         ["dataplane"], cls_conf=60)},
        asn=None, country="DE")
    assert su.extract_fields(row) == (
        "malicious", 60, "scanner", "dataplane", 1, "", "DE")


def test_extract_fields_non_malicious_rows_null_value_fields():
    """suspicious 行:verdict 入库但数值/列表字段全 NULL(即便带一条
    detected 且 malicious 的分类也不计数);benign/reserved 行同款。"""
    suspicious = _row(
        "198.51.100.5", "suspicious", 40,
        classifications={"scanner": _cls("scanner", "malicious", True,
                                         ["dataplane"])})
    assert su.extract_fields(suspicious) == (
        "suspicious", None, None, None, None, None, None)
    benign = _row("192.0.2.1", "benign", 0, is_reserved=True)
    assert su.extract_fields(benign) == (
        "benign", None, None, None, None, None, None)


def test_extract_fields_missing_verdict_raises():
    """无 verdict 行若落库 NULL 会永远留在待补集合里 → 分页死循环。
    协议破损,响亮失败(原样语义,错误类换成本模块的 ScanUnitsError)。"""
    row = _row("203.0.113.7", "", 0)
    row["threat"] = {}
    with pytest.raises(su.ScanUnitsError, match="missing threat.verdict"):
        su.extract_fields(row)


# ── 匿名内存口径(T7 原样;路径常量即注入接缝)──

def _smaps_inject(monkeypatch, tmp_path, anon_kb):
    """伪 /proc/self/smaps_rollup:Anonymous 值自由设定(kB)。"""
    p = tmp_path / "smaps_rollup"
    p.write_text(f"Rss: {anon_kb + 4096} kB\n"
                 f"Anonymous: {anon_kb} kB\n", encoding="ascii")
    monkeypatch.setattr(su, "_SMAPS_ROLLUP_PATH", str(p))
    return p


def test_current_anon_rss_mb_parses_anonymous_line(monkeypatch, tmp_path):
    _smaps_inject(monkeypatch, tmp_path, 20480)         # 20 MB
    assert su._current_anon_rss_mb() == 20.0


def test_current_anon_rss_mb_parse_failure_falls_back_warns_once(
        monkeypatch, tmp_path, capsys):
    """任何读取/解析失败(缺文件/缺 Anonymous 行/值非整数)→ 三者都回退
    ru_maxrss 口径,stderr 恰好告警一次(单进程只喊一嗓子),不抛异常。"""
    monkeypatch.setattr(su, "_current_rss_mb", lambda: 123.0)
    monkeypatch.setattr(su, "_anon_rss_fallback_warned", False)
    missing = tmp_path / "nope"                          # 文件不存在
    no_line = tmp_path / "no_anon_line"                  # 缺 Anonymous 行
    no_line.write_text("Rss: 100 kB\n", encoding="ascii")
    bad_value = tmp_path / "non_integer"                 # 值非整数
    bad_value.write_text("Anonymous: abc kB\n", encoding="ascii")
    for path in (missing, no_line, bad_value):
        monkeypatch.setattr(su, "_SMAPS_ROLLUP_PATH", str(path))
        assert su._current_anon_rss_mb() == 123.0        # 全部回退,不抛
    assert capsys.readouterr().err.count("WARNING") == 1


# ── scan_units 内存红线(真源夹具小库真跑)──

def _memory_db():
    db = sqlite3.connect(":memory:")
    return create_units(db)


def test_scan_units_memory_budget_exceeded(engine_env, monkeypatch, tmp_path):
    """每批提交后量一次匿名内存,超 --max-rss-mb 即停:第一批已落库,
    其余单元不再写 —— 爆顶死任务不死机器。"""
    _smaps_inject(monkeypatch, tmp_path, 1022976)        # 999 MB 匿名
    db = _memory_db()

    with pytest.raises(su.MemoryBudgetExceeded, match="anon.*140"):
        su.scan_units(engine_env["data_dir"], db, asof=ASOF, batch_rows=2)

    assert db.execute("SELECT COUNT(*) FROM units").fetchone()[0] == 2


def test_scan_units_peak_rss_anon_mb_tracks_max_sample(engine_env,
                                                       monkeypatch):
    """峰值 = 各批采样的 max(当前采样,非内核维护峰值)。采样值经
    _current_anon_rss_mb 桩逐批给(10 → 30 → 20 → 10)。"""
    samples = iter([10.0, 30.0, 20.0, 10.0, 10.0, 10.0, 10.0])
    monkeypatch.setattr(su, "_current_anon_rss_mb", lambda: next(samples))
    db = _memory_db()

    stats = su.scan_units(engine_env["data_dir"], db, asof=ASOF, batch_rows=2)

    assert stats["peak_rss_anon_mb"] == 30.0
    assert stats["units_total"] == 7


# ── require_scan_engine(引擎镜像太旧的报错话)──

def test_require_scan_engine_error_message(monkeypatch):
    """ipdb._scan 不可导入(镜像早于 #444)→ 带清楚话的错,不裸抛
    ImportError。sys.modules 里放 None 即「import 被禁止」的钉法。"""
    monkeypatch.setitem(sys.modules, "ipdb._scan", None)
    with pytest.raises(su.ScanUnitsError, match="引擎镜像早于 #444"):
        su.require_scan_engine()


def test_scan_units_anon_rss_falls_back_to_ru_maxrss(
        engine_env, monkeypatch, capsys):
    """整轮都读不到 smaps_rollup 的匿名行(路径不存在)→ 只告警一次,
    匿名内存读数回退成 ru_maxrss 总量,并进入本轮峰值(旧口径;
    #444 评审 P3-4,搬自旧 consensus_client 的整轮回退用例)。"""
    monkeypatch.setattr(su, "_SMAPS_ROLLUP_PATH", "/nonexistent/smaps_rollup")
    monkeypatch.setattr(su, "_anon_rss_fallback_warned", False)
    db = sqlite3.connect(":memory:")
    create_units(db)

    stats = su.scan_units(engine_env["data_dir"], db, asof=ASOF)

    err = capsys.readouterr().err
    assert err.count("cannot parse Anonymous") == 1
    # ru_maxrss 是进程至今的峰值,跑的过程中只增不减:回退值取到的
    # 峰值不会超过收尾时再读一次的值,也不会比它小太多(同一进程)
    assert 0 < stats["peak_rss_anon_mb"] <= su._current_rss_mb() + 0.01
    assert stats["peak_rss_anon_mb"] >= su._current_rss_mb() * 0.5
