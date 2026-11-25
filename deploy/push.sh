#!/usr/bin/env bash
# 每日黑名单 GitHub Release 发布:tag = 日期,产物 = Release assets
# 消费者: https://github.com/steponeerror/ip-radar-blocklist/releases/latest/download/top_100.txt
set -euo pipefail
# PAT 绝不出现在日志(不 set -x;若外部 wrap 了 set -x 也不继承)
if [[ $- == *x* ]]; then set +x; echo "[push.sh] set -x 已关闭(PAT 安全)" >&2; fi

REPO_DIR="${BLOCKLIST_REPO_DIR:-/opt/ip-radar-blocklist}"
REPO_API="https://api.github.com/repos/steponeerror/ip-radar-blocklist"
DATE="${RELEASE_DATE:-$(date -u +%Y-%m-%d)}"
TAG="v${DATE}"
FILES=(top_100.txt top_100.csv top_500.txt top_500.csv top_1000.txt top_1000.csv top_5000.txt top_5000.csv top_10000.txt top_10000.csv)

# 参数:--preflight 只验 token 读得到、/user 与仓库可读,不碰产物(#449)
PREFLIGHT=0
for arg in "$@"; do
    case "$arg" in
        --preflight) PREFLIGHT=1 ;;
        *) echo "[push.sh] 未知参数: $arg(用法: push.sh [--preflight])" >&2; exit 2 ;;
    esac
done

# token 只在这里读进变量;之后只以 -H "Authorization: Bearer …" 传给 curl,
# 绝不出现在任何输出/日志里(read_token 不打;失败只报来源,不报内容)。
read_token() {
    if [[ -n "${BLOCKLIST_PUSH_TOKEN:-}" ]]; then
        printf '%s' "$BLOCKLIST_PUSH_TOKEN"
    elif [[ -s /root/.config/blocklist-push.token && -r /root/.config/blocklist-push.token ]]; then
        cat /root/.config/blocklist-push.token
    else
        return 1
    fi
}
if ! TOKEN="$(read_token)"; then
    echo "[push.sh] 推送 token 读不到(env BLOCKLIST_PUSH_TOKEN 或 /root/.config/blocklist-push.token)— 放弃" >&2
    exit 1
fi

# gh_curl(#449):包一层 curl,输出 = curl 的输出 + 末尾一行 curl 的退出码。
# 传输层失败(断网、DNS、超时)时 curl 退出码非 0,输出里只有 000 或空 —— 退出码
# 经输出带回来(函数在 $( ) 里跑,改不了外层变量),让每个调用点走「不是 2xx」的
# 分支并打出原因。不包的话 set -e 会让脚本带着 curl 的退出码静默退出,和今天被
# 吞掉的 403 一样看不见。
gh_curl() {
    local out rc
    out=$(curl "$@") && rc=0 || rc=$?
    printf '%s\n%s' "$out" "$rc"
}

# --preflight(#449):坏 token 1 秒内失败,不再白跑 100 分钟生成才发现。
# 放在 cd/manifest 检查之前:预检只看 token,与产物无关。
if [[ $PREFLIGHT == 1 ]]; then
    RESP=$(gh_curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" https://api.github.com/user)
    CURL_RC=$(printf '%s' "$RESP" | tail -n 1)
    CODE=$(printf '%s' "$RESP" | sed '$d')
    if [[ "$CURL_RC" != 0 ]]; then
        echo "[push.sh] 预检:连不上 GitHub API(curl 退出码 $CURL_RC)— 放弃" >&2
        exit 1
    fi
    if [[ "$CODE" != "200" ]]; then
        echo "[push.sh] 预检:token 无效或已过期(HTTP $CODE)" >&2
        exit 1
    fi
    RESP=$(gh_curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" "$REPO_API")
    CURL_RC=$(printf '%s' "$RESP" | tail -n 1)
    CODE=$(printf '%s' "$RESP" | sed '$d')
    if [[ "$CURL_RC" != 0 ]]; then
        echo "[push.sh] 预检:连不上 GitHub API(curl 退出码 $CURL_RC)— 放弃" >&2
        exit 1
    fi
    if [[ "$CODE" != "200" ]]; then
        echo "[push.sh] 预检:token 访问不到仓库(HTTP $CODE)" >&2
        exit 1
    fi
    echo "[push.sh] 预检通过:token 可用、仓库可读(能不能建 Release 要到真正创建时才知道)"
    exit 0
fi

cd "$REPO_DIR"

# manifest 必须存在(本轮或上一轮成功产物)
if [[ ! -f manifest.json ]]; then
    echo "[push.sh] manifest.json 不存在 — 无可发布产物" >&2
    exit 1
fi

# 判断今天是否已发过(tag 已存在则跳过)
RESP=$(gh_curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "$REPO_API/releases/tags/$TAG")
CURL_RC=$(printf '%s' "$RESP" | tail -n 1)
TAG_STATUS=$(printf '%s' "$RESP" | sed '$d')
if [[ "$CURL_RC" != 0 ]]; then
    echo "[push.sh] 查今天的 tag 失败:连不上 GitHub API(curl 退出码 $CURL_RC)— 放弃" >&2
    exit 1
fi
if [[ "$TAG_STATUS" == "200" ]]; then
    echo "[push.sh] $TAG 已存在 — 跳过(如需重发先手动删除 Release + tag)"
    exit 0
fi

# 池摘要与核对读数(Release body)。读数来自本轮清单的 geo_stats(#444):
# 查了几个进榜地址、逐列核对一致几个、因扫描期间有源被重建而只核对了一部分几个
# —— 跳过的比例不设硬上限(用户 2026-11-25 裁:硬上限会让导出停更),写在这里让人看见。
# \n 是 JSON 转义换行——裸换行会让 JSON 非法 400,所以 python 输出的是两个字符的 \n。
# 读不到清单字段就写「?」,说明缺一行不该挡住发布。
READOUT=$(python3 - <<'PY' 2>/dev/null
import json
m = json.load(open('manifest.json'))
g = m.get('geo_stats') or {}
def n(key):
    v = g.get(key)
    return '?' if not isinstance(v, int) else str(v)
lines = [
    f"- Malicious pool: {m.get('malicious_pool', '?')} entries",
    f"- Geo check: {n('verified')} of {n('looked_up')} looked-up addresses verified column by column; "
    f"{n('drift_skipped')} checked only against the sources not rebuilt during the scan "
    f"(some of them not checked at all)",
    f"- Manifest generated at (UTC): {m.get('generated_at', '?')}",
]
print('\\n'.join(lines))
PY
) || READOUT='- Malicious pool: ?'
BODY="Daily IP blocklist export from the ip-radar consensus engine.\n\n${READOUT}\n- Tiers: 100 / 500 / 1000 / 5000 / 10000 (nested)\n- Release date: ${DATE}"

# api_message:从接口响应提取 message 字段(#449)。只回 message,绝不回整段响应
# 或请求 —— 403 正文里没有 PAT,但规则统一成「日志只出 HTTP 码 + message」。
api_message() {
    printf '%s' "$1" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('message') or '')
except Exception: print('')" 2>/dev/null
}

# 创建 Release。不用 curl -f:#449 生产教训 —— -f 把 403 的错误正文吞了,
# journal 只剩 status=22,看不出是 token 权限问题。改拿 HTTP 码 + message。
RELEASE_RESP=$(gh_curl -s -w '\n%{http_code}' -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "$REPO_API/releases" \
    -d "{\"tag_name\":\"$TAG\",\"name\":\"Blocklist $DATE\",\"body\":\"$BODY\",\"prerelease\":false,\"make_latest\":\"true\"}")
CURL_RC=$(printf '%s' "$RELEASE_RESP" | tail -n 1)
HTTP_CODE=$(printf '%s' "$RELEASE_RESP" | sed '$d' | tail -n 1)
RELEASE_BODY=$(printf '%s' "$RELEASE_RESP" | sed '$d' | sed '$d')
if [[ "$HTTP_CODE" != "201" ]]; then
    MSG="$(api_message "$RELEASE_BODY")"
    if [[ "$CURL_RC" != 0 ]]; then
        echo "[push.sh] 建 Release 失败:HTTP $HTTP_CODE — 连不上 GitHub API 或传输中断(curl 退出码 $CURL_RC)" >&2
    else
        echo "[push.sh] 建 Release 失败:HTTP $HTTP_CODE — ${MSG:-<接口无 message 字段>}" >&2
    fi
    if [[ "$HTTP_CODE" == "403" ]]; then
        echo "[push.sh] HTTP 403 多半是 token 没有建 Release 的权限:fine-grained token 需要 Contents: Read and write(见 deploy/README.md 第 5 步)" >&2
    fi
    exit 1
fi
RELEASE_ID=$(echo "$RELEASE_BODY" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "[push.sh] Release $TAG created (id=$RELEASE_ID)"

# 上传 assets
UPLOAD_URL="https://uploads.github.com/repos/steponeerror/ip-radar-blocklist/releases/$RELEASE_ID/assets"
for f in "${FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "[push.sh] WARNING: $f 不存在,跳过" >&2
        continue
    fi
    RESP=$(gh_curl -s -w '\n%{http_code}' \
        -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @"$f" \
        "${UPLOAD_URL}?name=$f")
    CURL_RC=$(printf '%s' "$RESP" | tail -n 1)
    STATUS=$(printf '%s' "$RESP" | sed '$d' | tail -n 1)
    if [[ "$STATUS" == "201" ]]; then
        echo "[push.sh] uploaded: $f ($(wc -c < "$f") bytes)"
    else
        if [[ "$CURL_RC" != 0 ]]; then
            echo "[push.sh] FAILED to upload $f:连不上 GitHub API 或传输中断(curl 退出码 $CURL_RC)" >&2
        else
            MSG="$(api_message "$(printf '%s' "$RESP" | sed '$d' | sed '$d')")"
            echo "[push.sh] FAILED to upload $f (HTTP $STATUS)${MSG:+ — $MSG}" >&2
        fi
        exit 1
    fi
done

echo "[push.sh] Release $TAG complete: https://github.com/steponeerror/ip-radar-blocklist/releases/tag/$TAG"
