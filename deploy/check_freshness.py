#!/usr/bin/env python3
"""断更告警(#448,2026-11-28):黑名单导出停更了没人知道。

读 manifest.json 的 generated_at,超过 --max-age-h(默认 36 小时,一轮
约 1.7–2 小时 + 每日一跑,36h = 缺两轮)就往告警通道发一条。背景:
2026-11-16、11-17 两晚轮次被 4h 上限杀掉,断更两天后才发现。

- 告警通道与引擎同源:环境变量 IP_RADAR_ALERT_URLS(apprise,逗号/空白
  分隔多个 URL;负载格式同 backend/ipdb/_alerts.py 的 push —— title/body
  两个文本字段,不新增凭据面)。URL 未设 = 不发,但 stderr 响亮一行
  (journal 里看得见),不静默。
- 文件不存在、读不出、时间解析不了 → 一律按过期处理(停更的最常见形态
  就是产物残缺,宁误报不漏报)。
- 每天最多一条:state 文件(--state,默认
  /var/lib/ipradar-blocklist/freshness-state.json)记上次告警的 UTC 日期,
  同一天重跑不重复轰炸;推送失败(apprise 返回 False/抛异常)不写 state,
  下次运行重试。
- 告警文本带 /var/log/ipradar-blocklist.log(#461)的最后几行,失败原因
  第一眼可见。
- 只查、只告警:不自动重跑导出,不改引擎。定时触发见
  deploy/ipradar-blocklist-freshness.{service,timer}(23:30 UTC,每轮
  预计完成之后;不用导出轮自己的 ExecStartPost —— 管线失败时那条不执行,
  恰恰是最需要告警的时刻)。

stdlib-only + apprise(惰性 import);测试注入缝:notify / now_fn 模块级
名字(monkeypatch 即可),路径全部参数化。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MANIFEST = Path("/opt/ip-radar-blocklist/manifest.json")
DEFAULT_LOG = Path("/var/log/ipradar-blocklist.log")
DEFAULT_STATE = Path("/var/lib/ipradar-blocklist/freshness-state.json")
DEFAULT_MAX_AGE_H = 36.0
LOG_TAIL_LINES = 5

# 注入缝(测试 monkeypatch 这两个名字)
notify = None          # 延迟到 _apprise_notify 赋值;测试直接替换
now_fn = lambda: datetime.now(timezone.utc)   # noqa: E731


def _manifest_age_h(path: Path, now: datetime) -> tuple[float | None, str]:
    """(generated_at 年龄小时, 读数说明)。任何读不出/解析不了 → (None, 原因),
    调方把 None 当过期。"""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        return None, f"manifest 读不到({e.strerror or e})"
    try:
        generated_at = json.loads(raw).get("generated_at")
    except (json.JSONDecodeError, AttributeError):
        return None, "manifest JSON 解析不了"
    if not isinstance(generated_at, str) or not generated_at:
        return None, "manifest 里没有 generated_at"
    try:
        gen = datetime.fromisoformat(generated_at)
    except ValueError:
        return None, f"generated_at 解析不了({generated_at!r})"
    if gen.tzinfo is None:
        gen = gen.replace(tzinfo=timezone.utc)
    return (now - gen).total_seconds() / 3600.0, f"上次生成 {generated_at}"


def _log_tail(path: Path, lines: int = LOG_TAIL_LINES) -> str:
    """日志最后几行;读不到就明说,不编造。"""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "(日志文件读不到)"
    stripped = [ln for ln in text.splitlines() if ln.strip()]
    if not stripped:
        return "(日志为空)"
    return "\n".join(stripped[-lines:])


def _alerted_today(state: Path, today: str) -> bool:
    try:
        return json.loads(state.read_text(encoding="utf-8")).get("last_alert") == today
    except (OSError, json.JSONDecodeError, AttributeError):
        return False


def _mark_alerted(state: Path, today: str) -> None:
    try:
        state.parent.mkdir(parents=True, exist_ok=True)
        tmp = state.with_suffix(".tmp")
        tmp.write_text(json.dumps(
            {"last_alert": today,
             "at": now_fn().isoformat(timespec="seconds")}) + "\n",
            encoding="utf-8")
        os.replace(tmp, state)
    except OSError as e:
        print(f"[check_freshness] state 写不进去({e}),明天可能重复告警一次",
              file=sys.stderr)


def _apprise_notify(title: str, body: str) -> bool:
    """引擎 _alerts.push 同款出口:IP_RADAR_ALERT_URLS 逗号/空白分隔;
    惰性 import;任何异常吞掉返回 False(跑在 timer 里,推送失败不得炸)。"""
    urls = [u for u in re.split(r",\s*|\s+",
                                os.environ.get("IP_RADAR_ALERT_URLS", "")) if u]
    if not urls:
        print("[check_freshness] IP_RADAR_ALERT_URLS 未设,告警发不出去"
              "(宿主机上把 URL 写进 /etc/ipradar-blocklist-alert.env,见"
              " deploy/README.md)", file=sys.stderr)
        return False
    try:
        import apprise  # 惰性:仅 env 非空才 import(同引擎约束 5)
        ap = apprise.Apprise()
        for url in urls:
            ap.add(url)
        return bool(ap.notify(title=title, body=body))
    except Exception as e:
        print(f"[check_freshness] apprise 推送失败:{e!r}(装了吗?"
              " pip install apprise)", file=sys.stderr)
        return False


notify = _apprise_notify


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    ap.add_argument("--state", type=Path, default=DEFAULT_STATE)
    ap.add_argument("--max-age-h", type=float, default=DEFAULT_MAX_AGE_H)
    args = ap.parse_args(argv)

    now = now_fn()
    today = now.strftime("%Y-%m-%d")
    age_h, note = _manifest_age_h(args.manifest, now)

    if age_h is not None and age_h <= args.max_age_h:
        print(f"[check_freshness] 未过期:{note}({age_h:.1f}h ≤ "
              f"{args.max_age_h:g}h)— 一切正常")
        return 0

    stale_note = (f"{note},已 {age_h:.1f}h" if age_h is not None
                  else f"{note}(按过期处理)")
    if _alerted_today(args.state, today):
        print(f"[check_freshness] 断更仍在({stale_note}),今天已告警过,不重复发")
        return 0

    title = "ip-radar 黑名单导出断更"
    body = (
        f"黑名单导出断更:{stale_note},超过 {args.max_age_h:g} 小时没有新产物。\n"
        "下一步:journalctl -u ipradar-blocklist.service 看失败原因;"
        "修好后 systemctl start ipradar-blocklist.service 重跑。\n"
        f"发布日志({args.log})最后 {LOG_TAIL_LINES} 行:\n{_log_tail(args.log)}"
    )
    if notify(title, body):
        _mark_alerted(args.state, today)
        print(f"[check_freshness] 断更告警已发({stale_note})")
    else:
        print("[check_freshness] 断更告警没发出去(state 不写,下次运行重试)",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
