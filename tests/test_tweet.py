"""tweet.py tests — 每日推文:文案组装 + 字符预算 + 防重 + 附图渲染。

纯离线:不 import requests/PIL 之外的第三方(附图用例 importorskip PIL)。
网络层(upload/post)不在此测 — 上线验收由手动真推覆盖。
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from deploy import tweet  # noqa: E402


def _row(ip="1.2.3.4", cc="US", classes="blacklist;scanner", conf="99",
         src="10", first="2026-09-30T16:22:20", last="2026-10-05T20:11:26+00:00"):
    return {"ip": ip, "asn": "64512", "country": cc, "classes": classes,
            "confidence": conf, "source_count": src, "first_seen": first, "last_seen": last}


# ---------------------------------------------------------------- 文案

def test_flag_valid_and_invalid():
    assert tweet.flag("US") == "\U0001F1FA\U0001F1F8"
    assert tweet.flag("RO") == "\U0001F1F7\U0001F1F4"
    for bad in ("", "X", "usa", "12"):
        assert tweet.flag(bad) == ""


def test_weighted_len_urls_count_23():
    body = "CSV: github.com/a/b/releases/latest/download/top_100.csv x"
    assert tweet.weighted_len("https://example.com/" + "z" * 100) == 23
    assert tweet.weighted_len(body) == tweet.weighted_len("CSV: " + "x" * 23 + " x")


def test_weighted_len_emoji_utf16():
    # utf-16 码元口径:国旗 = 2 个代理对 = 4;盾牌+VS16 = 3。高估方向 = 保守安全
    assert tweet.weighted_len("\U0001F1FA\U0001F1F8") == 4
    assert tweet.weighted_len("\U0001F6E1\uFE0F") == 3


def test_date_label_and_beijing_today():
    assert tweet.date_label("2026-10-06") == "Oct 6"
    assert tweet.date_label("2026-01-31") == "Jan 31"
    # UTC 21:00 起跑的轮次在北京已是次日
    assert tweet.beijing_today(datetime(2026, 10, 5, 21, 30, tzinfo=timezone.utc)) == "2026-10-06"


def test_compute_stats_excludes_provenance_labels():
    rows = [_row(), _row(cc="NL", classes="blacklist;abuse-reports;exploit;malware"),
            _row(cc="US", classes="blacklist;brute-force", conf="91")]
    s = tweet.compute_stats(rows)
    assert s["countries"] == [("US", 2), ("NL", 1)]
    names = [k for k, _ in s["classes"]]
    assert "blacklist" not in names and "abuse-reports" not in names
    # 四类全部 tie=1 → 按字母序取前三
    assert names == ["brute-force", "exploit", "malware"]
    assert s["avg_conf"] == 96  # round((99+99+91)/3)


def test_compose_text_shape_and_budget():
    rows = [_row(cc=c, classes=cl) for c, cl in
            [("US", "blacklist;exploit;malware"), ("US", "blacklist;scanner"),
             ("NL", "blacklist;brute-force"), ("RO", "blacklist;exploit")]]
    text = tweet.compose_text(tweet.compute_stats(rows), 251821, "Oct 6")
    assert "🛡️ ip-radar daily blocklist — Oct 6" in text
    assert "Tracking 251,821 malicious IPs" in text
    assert tweet.CSV_URL in text and tweet.REPO_URL in text
    assert "ip-radar consensus engine" in text
    assert tweet.HASHTAGS in text
    assert tweet.weighted_len(text) <= tweet.MAX_WEIGHTED_LEN


def test_compose_text_long_classnames_still_within_budget():
    rows = [_row(classes="abuse-reports;blacklist;brute-force;command-and-control;exploit;infected-system;malware;scanner;spam")
            for _ in range(100)]
    text = tweet.compose_text(tweet.compute_stats(rows), 251821, "Oct 6")
    assert tweet.weighted_len(text) <= tweet.MAX_WEIGHTED_LEN, text


# ---------------------------------------------------------------- 附图

def test_render_table_smoke(tmp_path):
    pytest.importorskip("PIL")
    out = tmp_path / "t.png"
    tweet.render_table([_row(ip="77.90.185.20", cc="DE",
                             classes="abuse-reports;blacklist;brute-force;exploit;malware;scanner",
                             conf="99", src="13")], out)
    assert out.stat().st_size > 1000  # 非空 PNG
