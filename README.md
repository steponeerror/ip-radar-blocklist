# ip-radar-blocklist

ip-radar(44 源聚合威胁情报引擎)的**每日黑名单导出**:对全部源证据重算
共识,产出嵌套阶梯 `top_{100,500,1000,5000,10000}.{txt,csv}` +
`manifest.json`,每日 commit 到 main,供防火墙 / ipset / fail2ban / 研究直接取用。

导出物是对全部源证据**重算出的共识衍生数据**,视为新数据:**不设再分发
限制**(2026-10-03 拍板,推翻早先的净源 allowlist 方案;不做逐源许可审计,
不做 firehol/ipsum 聚合器剔除)。

数据来源:ip-radar 引擎(全票制共识;单元宇宙 smoke 实测 ~3.5M,恶意池
规模待 run #1 实证)。引擎仓库
`pi-ip-lookup-tool`(GitHub: steponeerror/ip-radar);本仓只**只读引用**
引擎代码与 LMDB 分片,不复制、不重实现共识——逐单元采样活引擎
`POST /api/query/stream`。

## 产物

| 文件 | 内容 |
|---|---|
| `top_N.txt` | 纯数据行:每行一个单元(IP 或 CIDR 原文),无表头无注释,UTF-8、LF、EOF 恰一换行 —— `ipset restore` / `iptables-restore` 直吃 |
| `top_N.csv` | 表头逐字 9 列:`ip,asn,country,classes,confidence,source_count,sources,first_seen,last_seen`(RFC4180 引号规则) |
| `manifest.json` | 本轮元数据(字段见下);失败时为 error manifest |

- N ∈ {100, 500, 1000, 5000, 10000},**嵌套超集**:所有档位出自同一排序
  的不同 LIMIT 前缀,`top_100.txt` 恒为 `top_500.txt` 的前缀。
- 档位文件**恒存在**("up to N"):池小于档位 → 行数即真实数;空池 →
  txt 空文件 + csv 仅表头。

## 裁决表(15 项,2026-10-03 共识)

| # | 裁决 |
|---|---|
| 1 | schema 9 列:`ip,asn,country,classes,confidence,source_count,sources,first_seen,last_seen`;`first_seen` = 该单元全源证据 first_seen 的 min(walk 阶段按 ISO 文本比较)。(2026-10-03 Q5-B 逆转条款生效:run #1 实测恶意池 first_seen 覆盖率 41.5%,列于首次公开发布前加回) |
| 2 | 排序:`source_count DESC → confidence DESC → last_seen DESC NULLS LAST → ip ASC`(末键保跨轮确定性) |
| 3 | 档位恒存在,up to N(行数即真实数,不虚补不缺席) |
| 4 | v4/v6 混装单文件,不拆族 |
| 5 | 记录原生粒度:引擎记什么出什么 —— /32 出纯 IP、CIDR 出 CIDR 原文 |
| 6 | CIDR 锚点共识语义:lookup 采网络地址(去前缀),判定盖整段;段内 /32 各自独立成条,嵌套冗余(/24 与其内 /32 都达标)两条都出,不消除 |
| 7 | `source_count` = 全部 detected 且 verdict=="malicious" 的 classification 里 **distinct 源名计数**(跨 classification 去重) |
| 8 | 入选口径:引擎融合判定 `threat.verdict == "malicious"`;suspicious 不入选(verdict 入库仅作过滤凭证) |
| 9 | `classes` = 同口径 classification type 并集,排序去重分号连接;`confidence` = `threat.confidence`;`asn`/`country` = MergedField 胜者 `str(value)`,缺失留空 |
| 10 | `last_seen` = 该单元全源证据 last_seen 的 max(walk 阶段按 ISO 文本比较) |
| 11 | 许可口径:全源重算共识衍生数据,无再分发限制 |
| 12 | 发布形态:每日 commit 到 main |
| 13 | 失败语义:产物先写 `.staging/`(gitignored),校验后逐文件原子 `os.replace` 换入,`manifest.json` **最后落**(消费者可见提交点);失败只写带 `error` 的 manifest.json,**保留前次产物原封不动** |
| 14 | API 契约:`POST /api/query/stream`,body `{"ips": [...]}`,NDJSON 流响应;每请求带 `x-ipradar-client: web` 头 + `Authorization: Bearer <key>`(引擎查询端点强制 key 鉴权,非同源无 key 即 401;key 经 `--api-key`/env `IPRADAR_API_KEY` 传入,置备见 deploy/README);请求起点配速 ≥1.1s(引擎 keyed 限流 60/min);429 按错误信封 `retry_after` 等待后重试同块(不耗重试预算,单轮 ≤10 次,超出响亮终止);每块 3 次指数退避(2/4/8s)重试后仍失败 → 整轮终止 |
| 15 | 内存红线:全程流式 + sqlite 为唯一中间态,分块 ≤2500(在飞仅几 MB),进程 `ru_maxrss` 自检(默认 140MB)超限主动终止 —— **爆顶死任务不死机器** |

## 运行手册

### 本地

CLI(`--data-dir`、`--api-base` 必填;`--out-dir` 默认仓根,
`--engine-path` 默认本机引擎 backend,`--api-key` 默认取 env
`IPRADAR_API_KEY`):

```bash
export IPRADAR_API_KEY=<key>   # 或显式传 --api-key <key>
python scripts/generate_blocklist.py \
  --engine-path /home/huxiao/dev/pi-ip-lookup-tool/backend \
  --data-dir    /home/huxiao/dev/pi-ip-lookup-tool/backend/data \
  --api-base    http://127.0.0.1:8000
```

**本地 run #1 同样需要 key**:引擎查询端点(`POST /api/query/stream`)
挂了 `api_key_dep`,非同源程序化请求无 key 即 401 永久中止 —— 先起本地
引擎,浏览器同源打开 Admin UI(`/admin`)→ API Keys → 创建一枚 key
再跑(服务器侧置备步骤见 `deploy/README.md`)。客户端对 429 自容忍:
按信封 `retry_after` 等待重试;请求起点配速 ≥1.1s。

成功:manifest JSON 打到 stdout(机器可读),每阶段一行带计数的进度走
stderr,退出码 0。失败:error manifest 打到 stderr,退出码 1。

belt-and-braces:cgroup 级内存上限兜底(红线 #15 之外的机器保险):

```bash
systemd-run --scope -p MemoryMax=1G \
  python scripts/generate_blocklist.py --data-dir ... --api-base ...
```

跑测试(引擎 venv + 只读 PYTHONPATH;LMDB 真分片 + 真协议 stub,无网络):

```bash
PYTHONPATH=/home/huxiao/dev/pi-ip-lookup-tool/backend \
  /home/huxiao/dev/pi-ip-lookup-tool/backend/.venv/bin/pytest tests/ -v
```

### 服务器(demo)

部署资产由 Task 5 交付在 `deploy/`(docker compose exporter 容器 + systemd
timer + PAT push 脚本,届时见该目录注释):exporter 以 sidecar 容器复用
引擎镜像(`mem_limit: 150m`,
LMDB 数据卷只读挂载,容器网络直连 `http://ipradar:8000`),systemd
timer 每日触发 `docker compose run --rm blocklist-exporter`,产物落仓目录
后由 push 脚本 commit 并推 main。PAT 从 env `BLOCKLIST_PUSH_TOKEN` 或
0600 权限的 token 文件注入,**永不进仓库**。

## 内存红线与失败语义(展开)

- 三段全流式:LMDB 游标枚举(executemany ≤2500/批)、NDJSON 逐行消费、
  sqlite 游标直写档位文件;单元集合从不物化进 Python list/dict。
- 中间态唯一落点 `out_dir/.staging/work.db`(gitignored);轮次开始先删
  陈旧 work.db,成功后清空 `.staging`。
- 任何阶段异常(含 RSS 超限、API 重试耗尽、分片校验不符)→ 只覆写
  `manifest.json`(error + 已知阶段与部分统计),已发布档位文件不动。

## manifest 字段说明

| 字段 | 含义 |
|---|---|
| `generated_at` | 本轮时间戳,ISO 8601 UTC |
| `tiers` | `{"100": 行数, ...}` 每档实际行数(up to N) |
| `universe` | walk 枚举到的候选单元总数 |
| `malicious_pool` | verdict=="malicious" 的池大小 |
| `cidr_units` / `units_v6` | 池内 CIDR / v6 单元数 |
| `first_seen_coverage` | 恶意池内 `first_seen` 非空占比 |
| `walk_stats` | T1 统计(units_total/units_v4/units_v6/cidr_units/per_source/first_seen_coverage/skipped_anomalies) |
| `enrich_stats` | T2 统计(queried/malicious/requests/retries/rate_limited/elapsed_s) |
| `elapsed_s` | 全管线耗时(秒) |
| `peak_rss_mb` | 进程峰值 RSS(ru_maxrss) |
| `api_base` | 本轮采样的引擎 API 基址 |
| `error` | 仅失败轮出现:失败描述(带 `[阶段]` 前缀) |

## 开发

- `scripts/universe_walk.py`(T1)→ `consensus_client.py`(T2)→
  `emit_tiers.py`(T3)→ `generate_blocklist.py`(T4 编排);零第三方
  依赖(Python 3.12 stdlib + 引擎自带的 lmdb)。
- 引擎是**只读引用**:`--engine-path` 注入 sys.path,`IP_RADAR_DATA_DIR`
  由 `--data-dir` 旗标决定(registry import 期消费);不改引擎仓任何文件。
- 测试同上「跑测试」;集成测试以真子进程跑 CLI(真 LMDB 分片 + 真协议
  stub API),失败路径含真实 2/4/8s 退避,全量 ~25s。
