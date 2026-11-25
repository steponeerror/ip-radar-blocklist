"""push.sh tests — 发布脚本:--preflight 预检 + 失败可见(HTTP 码 + message 字段)
+ PAT 绝不出现在 stdout/stderr(#449:2026-11-25 生产上 403 被 curl -f 吞掉,
白跑 100 分钟才失败,journal 只剩 status=22)。

手法:临时目录里放一个假 curl(可执行 bash 脚本),按环境变量 STUB_MODE 返回
预写响应,把收到的参数追加到 CURL_LOG;把桩所在目录放到 PATH 最前面,用
subprocess 跑 deploy/push.sh。桩的响应里只有假数据,测试 token 用字符串
dummy-token-123 —— 桩和日志都不含真实凭证。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PUSH_SH = REPO_ROOT / "deploy" / "push.sh"
TOKEN = "dummy-token-123"
FILES = ["top_100.txt", "top_100.csv", "top_500.txt", "top_500.csv",
         "top_1000.txt", "top_1000.csv", "top_5000.txt", "top_5000.csv",
         "top_10000.txt", "top_10000.csv"]

# 与 deploy/push.sh 的 FILES 名单逐字一致;脚本若改名单,这里跟着改
CURL_STUB = '''#!/usr/bin/env bash
# push.sh 测试替身:按 STUB_MODE 返回预写响应;全部参数追加到 CURL_LOG。
# 识别顺序:/user → /releases/tags/ → uploads.github.com → 建 Release。
set -u
printf '%s\\n' "$*" >> "${CURL_LOG:?CURL_LOG 未设置}"
MODE="${STUB_MODE:-}"

# net_down:curl 传输层失败的样子 —— 退出码 7(连不上),-w 的 http_code 是 000
if [[ "$MODE" == "net_down" ]]; then printf '000'; exit 7; fi
# create_net_down:只有「建 Release」那一次调用连不上(查 tag 正常)
if [[ "$MODE" == "create_net_down" && "$*" == *"api.github.com/repos/"*"/releases"* && "$*" != *"/releases/tags/"* ]]; then
    printf '\n000'; exit 7
fi

if [[ "$*" == *"https://api.github.com/user"* ]]; then
    if [[ "$MODE" == "user_401" ]]; then printf '401'; else printf '200'; fi
    exit 0
fi
if [[ "$*" == *"/releases/tags/"* ]]; then
    printf '404'   # tag 不存在 → 走建 Release 路径
    exit 0
fi
if [[ "$*" == *"-o /dev/null"* && "$*" == *"api.github.com/repos/steponeerror/ip-radar-blocklist"* ]]; then
    printf '200'   # 预检的仓库可读检查(建 Release/上传不带 -o,不会误入此支)
    exit 0
fi
if [[ "$*" == *"https://uploads.github.com/"* ]]; then
    if [[ "$MODE" == "upload_500" && "$*" == *"name=top_500.txt"* ]]; then
        printf '{"message":"Boom"}\\n500'
    else
        printf '{"id":1}\\n201'   # 真 GitHub 上传成功会带一段 JSON 正文
    fi
    exit 0
fi
if [[ "$*" == *"api.github.com/repos/"*"/releases"* ]]; then
    if [[ "$MODE" == "create_403" ]]; then
        printf '{"message":"Resource not accessible by personal access token","documentation_url":"https://docs.github.com/rest"}\\n403'
    else
        printf '{"id":12345,"tag_name":"vTEST"}\\n201'
    fi
    exit 0
fi
printf '{"message":"stub: unexpected call"}\\n000'
exit 1
'''


@pytest.fixture
def stub_env(tmp_path):
    """假 curl + 假仓目录(清单 + 十个档位)+ 指向桩的环境变量。"""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "curl"
    stub.write_text(CURL_STUB, encoding="utf-8")
    stub.chmod(0o755)
    # push.sh 的 JSON 解析用 python3;钉住测试进程自己的解释器,不赌 PATH
    (bin_dir / "python3").symlink_to(sys.executable)
    log = tmp_path / "curl.log"
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "manifest.json").write_text(json.dumps({
        "malicious_pool": 2335102,
        "geo_stats": {"looked_up": 10000, "verified": 9235,
                      "drift_skipped": 765, "generated_at": "2026-11-25T03:00:00Z"},
    }), encoding="utf-8")
    for f in FILES:
        (repo / f).write_text("x", encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["CURL_LOG"] = str(log)
    env["BLOCKLIST_REPO_DIR"] = str(repo)
    env["BLOCKLIST_PUSH_TOKEN"] = TOKEN
    env.pop("RELEASE_DATE", None)
    env.pop("STUB_MODE", None)
    return {"env": env, "log": log}


def _run(env, *args):
    r = subprocess.run(["bash", str(PUSH_SH), *args],
                       env=env, capture_output=True, text=True, timeout=60)
    # 每一条用例都盯住:PAT 绝不进 stdout/stderr(#449)
    assert TOKEN not in r.stdout and TOKEN not in r.stderr, "PAT 进了输出"
    return r


# ---------------------------------------------------------------- --preflight

def test_preflight_ok(stub_env):
    r = _run(stub_env["env"], "--preflight")
    assert r.returncode == 0, r.stderr
    assert "预检通过" in r.stdout


def test_preflight_user_401(stub_env):
    env = dict(stub_env["env"])
    env["STUB_MODE"] = "user_401"
    r = _run(env, "--preflight")
    assert r.returncode == 1
    assert "HTTP 401" in r.stderr


def test_preflight_network_down_says_cannot_reach(stub_env):
    """连不上 GitHub API 时要说「连不上」并带 curl 退出码,不能说成 token 过期。"""
    env = dict(stub_env["env"])
    env["STUB_MODE"] = "net_down"
    r = _run(env, "--preflight")
    assert r.returncode == 1
    assert "连不上" in r.stderr
    assert "退出码 7" in r.stderr
    assert "过期" not in r.stderr


def test_read_only_calls_carry_timeouts_and_retries(stub_env):
    """只读的三次调用(预检两次、查 tag 一次)自带连接超时、总超时和重试:
    网络黑洞时不能等 curl 默认的 300 秒;短暂抖动自己重试掉,别让整轮没了。"""
    pre = _run(stub_env["env"], "--preflight")
    assert pre.returncode == 0, pre.stderr          # 调了 /user 和仓库这两次
    r = _run(stub_env["env"])
    assert r.returncode == 0, r.stderr              # 调了查 tag 这一次
    log = stub_env["log"].read_text().splitlines()
    for needle in ("api.github.com/user", "/releases/tags/", "api.github.com/repos/steponeerror/ip-radar-blocklist"):
        calls = [ln for ln in log if needle in ln and "-o /dev/null" in ln]
        assert calls, needle
        for ln in calls:
            for flag in ("--connect-timeout 10", "--max-time 30", "--retry 2", "--retry-delay 5", "--retry-connrefused"):
                assert flag in ln, (needle, flag)


def test_tag_check_network_down_reports_instead_of_silent_exit(stub_env):
    """查 tag 那一步连不上:以前被 set -e 静默杀掉(退出码 7、一行字都没有)。"""
    env = dict(stub_env["env"])
    env["STUB_MODE"] = "net_down"
    r = _run(env)
    assert r.returncode == 1
    assert "查今天的 tag" in r.stderr
    assert "连不上" in r.stderr
    assert "退出码 7" in r.stderr


def test_create_release_network_down_reports_http_000(stub_env):
    env = dict(stub_env["env"])
    env["STUB_MODE"] = "create_net_down"
    r = _run(env)
    assert r.returncode == 1
    assert "建 Release 失败" in r.stderr
    assert "HTTP 000" in r.stderr
    assert "退出码 7" in r.stderr


# ---------------------------------------------------------------- 建 Release

def test_create_release_403_message_and_hint_never_token(stub_env):
    env = dict(stub_env["env"])
    env["STUB_MODE"] = "create_403"
    r = _run(env)
    assert r.returncode == 1
    assert "HTTP 403" in r.stderr
    assert "Resource not accessible" in r.stderr          # 接口 message 字段
    assert "Contents: Read and write" in r.stderr         # 403 专属提示
    assert TOKEN not in r.stdout and TOKEN not in r.stderr  # PAT 绝不进输出
    assert "documentation_url" not in r.stderr            # 只打 message,不打整段响应


def test_success_creates_and_uploads_all_ten(stub_env):
    r = _run(stub_env["env"])
    assert r.returncode == 0, r.stderr
    assert "complete" in r.stdout
    log = stub_env["log"].read_text()
    uploads = [ln for ln in log.splitlines() if "uploads.github.com" in ln]
    assert len(uploads) == 10, uploads
    for f in FILES:
        assert any(f"name={f}" in ln for ln in uploads), f


def test_upload_500_reports_code_and_message(stub_env):
    env = dict(stub_env["env"])
    env["STUB_MODE"] = "upload_500"
    r = _run(env)
    assert r.returncode == 1
    assert "HTTP 500" in r.stderr
    assert "Boom" in r.stderr   # 接口 message 字段也带出来(#449 新行为)
