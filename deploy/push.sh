#!/usr/bin/env bash
# 每日黑名单 GitHub Release 发布:tag = 日期,产物 = Release assets
# 消费者: https://github.com/steponeerror/ip-radar-blocklist/releases/latest/download/top_100.txt
set -euo pipefail
# PAT 绝不出现在日志(不 set -x;若外部 wrap 了 set -x 也不继承)
if [[ $- == *x* ]]; then set +x; echo "[push.sh] set -x 已关闭(PAT 安全)" >&2; fi

REPO_DIR="/opt/ip-radar-blocklist"
REPO_API="https://api.github.com/repos/steponeerror/ip-radar-blocklist"
TOKEN="${BLOCKLIST_PUSH_TOKEN:-$(cat /root/.config/blocklist-push.token)}"
DATE="${RELEASE_DATE:-$(date -u +%Y-%m-%d)}"
TAG="v${DATE}"
FILES=(top_100.txt top_100.csv top_500.txt top_500.csv top_1000.txt top_1000.csv top_5000.txt top_5000.csv top_10000.txt top_10000.csv manifest.json)

cd "$REPO_DIR"

# manifest 必须存在(本轮或上一轮成功产物)
if [[ ! -f manifest.json ]]; then
    echo "[push.sh] manifest.json 不存在 — 无可发布产物" >&2
    exit 1
fi

# 判断今天是否已发过(tag 已存在则跳过)
TAG_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "$REPO_API/releases/tags/$TAG")
if [[ "$TAG_STATUS" == "200" ]]; then
    echo "[push.sh] $TAG 已存在 — 跳过(如需重发先手动删除 Release + tag)"
    exit 0
fi

# 池摘要(Release body;\n 是 JSON 转义换行——裸换行会让 JSON 非法 400)
POOL=$(python3 -c "import json; print(json.load(open('manifest.json')).get('malicious_pool','?'))" 2>/dev/null || echo "?")
BODY="Daily IP blocklist export from the ip-radar consensus engine.\n\n- Malicious pool: ${POOL} entries\n- Tiers: 100 / 500 / 1000 / 5000 / 10000 (nested)\n- Generated: ${DATE} (UTC)"

# 创建 Release
RELEASE_RESP=$(curl -sf -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "$REPO_API/releases" \
    -d "{\"tag_name\":\"$TAG\",\"name\":\"Blocklist $DATE\",\"body\":\"$BODY\",\"prerelease\":false,\"make_latest\":\"true\"}")
RELEASE_ID=$(echo "$RELEASE_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "[push.sh] Release $TAG created (id=$RELEASE_ID)"

# 上传 assets
UPLOAD_URL="https://uploads.github.com/repos/steponeerror/ip-radar-blocklist/releases/$RELEASE_ID/assets"
for f in "${FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "[push.sh] WARNING: $f 不存在,跳过" >&2
        continue
    fi
    STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @"$f" \
        "${UPLOAD_URL}?name=$f")
    if [[ "$STATUS" == "201" ]]; then
        echo "[push.sh] uploaded: $f ($(wc -c < "$f") bytes)"
    else
        echo "[push.sh] FAILED to upload $f (HTTP $STATUS)" >&2
        exit 1
    fi
done

echo "[push.sh] Release $TAG complete: https://github.com/steponeerror/ip-radar-blocklist/releases/tag/$TAG"
