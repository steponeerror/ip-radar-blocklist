"""check_freshness 测试(#448):三类异常各一条 + 新鲜不发 + 当天不重复。

手法:路径全部参数化(tmp_path),推送出口 monkeypatch 模块级 `notify`
(记录调用,返回可控),时钟 monkeypatch `now_fn`(钉死判定时刻)。
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "deploy"))

import check_freshness as cf   # noqa: E402


NOW = datetime(2026, 11, 28, 23, 30, tzinfo=timezone.utc)


def _manifest(path: Path, generated_at="2026-11-28T03:00:00+00:00"):
    payload = {"malicious_pool": 2335102}
    if generated_at is not None:
        payload["generated_at"] = generated_at
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.fixture
def env(tmp_path, monkeypatch):
    calls = []

    def fake_notify(title, body):
        calls.append((title, body))
        return True

    monkeypatch.setattr(cf, "notify", fake_notify)
    monkeypatch.setattr(cf, "now_fn", lambda: NOW)
    return {
        "manifest": tmp_path / "manifest.json",
        "log": tmp_path / "ipradar-blocklist.log",
        "state": tmp_path / "state.json",
        "calls": calls,
    }


def _run(env, max_age_h=36.0):
    return cf.main([
        "--manifest", str(env["manifest"]),
        "--log", str(env["log"]),
        "--state", str(env["state"]),
        "--max-age-h", str(max_age_h),
    ])


def test_fresh_manifest_sends_nothing(env):
    _manifest(env["manifest"], "2026-11-28T03:00:00+00:00")   # 20.5h 前
    assert _run(env) == 0
    assert env["calls"] == []


def test_stale_manifest_sends_alert_with_next_step_and_log_tail(env):
    """超 36h → 发一条;文本带「发生了什么 + 下一步怎么办」(#383 判例)
    和发布日志最后几行(#461 并入)。"""
    _manifest(env["manifest"], "2026-11-27T03:00:00+00:00")   # 44.5h 前
    env["log"].write_text("[push.sh] line1\n[push.sh] 建Release失败\n"
                          "[push.sh] line3\n[push.sh] line4\n[push.sh] line5\n"
                          "[push.sh] line6\n[push.sh] line7\n", encoding="utf-8")
    assert _run(env) == 0
    assert len(env["calls"]) == 1
    title, body = env["calls"][0]
    assert "断更" in title
    assert "journalctl -u ipradar-blocklist.service" in body
    assert "systemctl start ipradar-blocklist.service" in body
    assert "line7" in body and "line1" not in body   # 尾巴,不是全文
    # state 落盘:当天再跑不再发
    assert _run(env) == 0
    assert len(env["calls"]) == 1


def test_same_day_rerun_does_not_repeat(env):
    _manifest(env["manifest"], "2026-11-27T03:00:00+00:00")
    assert _run(env) == 0
    assert _run(env) == 0
    assert len(env["calls"]) == 1


def test_missing_manifest_treated_stale(env):
    """文件不存在 → 按过期(三类异常之一)。"""
    assert not env["manifest"].exists()
    assert _run(env) == 0
    assert len(env["calls"]) == 1
    assert "读不到" in env["calls"][0][1]


def test_unparseable_manifest_treated_stale(env):
    """JSON 坏 / 时间解析不了 → 按过期(三类异常之二、之三)。
    (每次用全新 state:同一天只告一次的节流见 test_same_day_rerun。)"""
    env["manifest"].write_text("{not json", encoding="utf-8")
    assert _run(env) == 0
    assert len(env["calls"]) == 1
    env["state"].unlink()
    env["manifest"].write_text(json.dumps({"generated_at": "day-before-yesterday"}),
                               encoding="utf-8")
    assert _run(env) == 0
    assert len(env["calls"]) == 2
    assert "解析不了" in env["calls"][1][1]


def test_error_manifest_alerts_even_when_fresh(env):
    """评审 A(必须改):失败轮的清单被 write_error_manifest 用失败当时
    的时间覆写,只看 generated_at 会永远「新鲜」→ 告警永不发。error 键
    非空 = 上一轮失败,按过期处理,正文带原因(含 ScanUnitsError);
    同日不重复。"""
    _manifest(env["manifest"], "2026-11-28T23:00:00+00:00")   # 半小时前,足够「新鲜」
    payload = json.loads(env["manifest"].read_text(encoding="utf-8"))
    payload["error"] = "[scan] ScanUnitsError: row '1.2.3.5': threat missing confidence"
    env["manifest"].write_text(json.dumps(payload), encoding="utf-8")
    assert _run(env) == 0
    assert len(env["calls"]) == 1
    assert "ScanUnitsError" in env["calls"][0][1]
    assert "上一轮失败" in env["calls"][0][1]
    assert _run(env) == 0
    assert len(env["calls"]) == 1


def test_push_failure_does_not_write_state_and_fails(env, monkeypatch):
    """推送失败 → 退出码 1、state 不写(下次运行重试,不当成已告警)。"""
    _manifest(env["manifest"], "2026-11-27T03:00:00+00:00")
    monkeypatch.setattr(cf, "notify", lambda t, b: False)
    assert _run(env) == 1
    assert not env["state"].exists()


def test_max_age_h_is_tunable(env):
    """阈值可调:同一条 20.5h 前的产物,卡 12h 线也算断更。"""
    _manifest(env["manifest"], "2026-11-28T03:00:00+00:00")
    assert _run(env, max_age_h=12.0) == 0
    assert len(env["calls"]) == 1
