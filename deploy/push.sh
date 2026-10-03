#!/usr/bin/env bash
# push.sh — 宿主机侧的夜间推送(生成在容器,推送在宿主机,见 deploy/README.md)。
# 触发方:ipradar-blocklist.service 的 ExecStartPost(仅生成成功后运行);
# 可手工执行做补推。PAT 来源:$BLOCKLIST_PUSH_TOKEN 或
# /root/.config/blocklist-push.token(0600,root 属主)。
set -euo pipefail

REPO=/opt/ip-radar-blocklist
TOKEN_FILE=/root/.config/blocklist-push.token

# 铁律:本脚本永不开 set -x,也不得被 set -x 的调用方包裹 ——
# 推送 URL 内嵌 PAT,任何 shell 回显都会把 token 写进 journal/日志。
cd "$REPO"

# 导出器容器以 root 写产物;若 checkout 属主非 root,git >=2.35.2 会以
# "dubious ownership" 拒绝。仅在真的被拒时才给**这一个仓库**加白名单
# (幂等:重复 --add 无害;全局不放宽其他仓库)。
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git config --global --add safe.directory "$REPO"
fi

# 产物契约(README 产物节):档位恒存在 up-to-N,首轮后必齐。
# nullglob 防首轮缺失时把字面量 top_*.txt 喂给 git add 崩掉。
shopt -s nullglob
artifacts=(top_*.txt top_*.csv manifest.json)
shopt -u nullglob
if [ "${#artifacts[@]}" -eq 0 ]; then
    echo "FATAL: $REPO 下无产物(top_*.txt / top_*.csv / manifest.json)——先跑生成" >&2
    exit 1
fi
git add -- "${artifacts[@]}"

if git diff --cached --quiet; then
    echo "no changes"
    exit 0
fi

git -c user.name=ip-radar-exporter -c user.email=noreply@steponeerror \
    commit -m "nightly export $(date -u +%FT%TZ)"

# PAT:env 优先(交互覆盖),否则 0600 token 文件;$(...) 自动去尾换行。
# token 永不 echo、永不落仓库、不写进 .git/config(仅活在下面的进程参数里)。
TOKEN="${BLOCKLIST_PUSH_TOKEN:-$(cat "$TOKEN_FILE")}"
if [ -z "$TOKEN" ]; then
    echo "FATAL: 无推送 token(设 $BLOCKLIST_PUSH_TOKEN 或写 $TOKEN_FILE)" >&2
    exit 1
fi

# 残余风险(单管理员机器,已接受,如实记录):
#  1) 推送进行中的几秒里,内嵌 token 的 URL 出现在 git push 进程的
#     /proc/<pid>/cmdline —— Linux 默认连 root 进程的 cmdline 也对其他
#     本机用户可读(hidepid 未开时)。更重的 credential-helper 方案对本
#     场景过度设计,故按定案取最简安全形态并如实标注。
#  2) sed 抹除假设 PAT 不含正则元字符 —— GitHub PAT(github_pat_…/40-hex)
#     均满足;若换成含元字符的凭据,先改这里的转义。
PUSH_URL="https://x-access-token:${TOKEN}@github.com/steponeerror/ip-radar-blocklist.git"
git push "$PUSH_URL" main 2>&1 | sed "s/${TOKEN}/***/g"

unset TOKEN PUSH_URL

# 终态校验:commit+push 后工作树必须干净(.staging/ 已 gitignore 不现身)。
# 不干净 = 有预期外残留,响亮失败而不是静默吞掉。
if [ -n "$(git status --porcelain)" ]; then
    echo "WARN: 推送后工作树不干净,人工检查:" >&2
    git status --porcelain >&2
    exit 1
fi
