# ip-radar-blocklist

ip-radar(44 源聚合情报引擎)的每日黑名单导出:自动生成 ~10 万条恶意 IP 的
CSV,公开于 GitHub,供防火墙 / fail2ban / 研究直接取用。

## 定位(2026-09-29 与维护者对齐,方向已拍板)

**A 为主、附带 B 的表头** —— 一份数据、两种产物:

| 产物 | 内容 | 用途 |
|---|---|---|
| `ips.txt` | 纯 IP 一列(每行一个) | 防火墙 / fail2ban / iptables 直接 import |
| `blocklist.csv` | `ip,verdict,confidence,classes,source_count,last_seen` | 展示 / 分析 / rich 消费 |

选数标准(A 档,保守实用):**共识判定 = malicious**,按置信度/源数排序截
100k。不出 suspicious(提示级不进防火墙清单)。

## 数据来源

- ip-radar server:44 源聚合、威胁记录 ~67 万、全票制共识引擎
- 生产实例:demo 服务器(`/opt/ip-lookup-tool`,docker + LMDB)
- server 仓库:`~/dev/pi-ip-lookup-tool`(GitHub: steponeerror/ip-radar)
- 本地 fail2ban 先例:server 仓 `scripts/fail2ban/`

## 待定问题(实现前必须逐个拍板)

1. **任务在哪跑**:demo 服务器 cron 直接读库 + `git push`(推荐,数据在那,
   Actions 拉不到库)vs GitHub Actions 经公开 API 拉
2. **选数细则**:排序键(置信度?源数?最近活跃?)、IPv4/IPv6 拆分、单 IP
   vs 网段、截断边界
3. ✅ **许可口径(2026-09-29 拍板,2026-10-03 推翻重定)**:全源重算 —— 导出物是对全部源证据重算出的共识衍生数据,视为新数据,**不设再分发限制、不做净源 allowlist**;不做逐源许可审计,不做 firehol/ipsum 聚合器剔除。
4. **发布形态**:产物 commit 到 main / 每日 GitHub Release / gh-pages
5. **凭据**:服务器 push 用的 fine-grained PAT(只写本仓)

## 状态

脚手架(2026-09-29 建立),设计讨论进行中 —— 见上「待定问题」。
