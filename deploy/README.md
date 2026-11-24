# deploy/ — 服务器部署资产(ip-radar-blocklist 每日导出)

服务器(demo,964Mi RAM)上的一键部署包:**容器生成、宿主机推送**。
本目录只交付资产;部署本身是操作人动作,按下述步骤执行。

## 运行形态

```
systemd timer (每日 04:30, Persistent=true)
  └─ ipradar-blocklist.service (Type=oneshot, root, idle 优先级)
       ├─ ExecStart:     docker compose run --rm blocklist-exporter
       │                  (容器: 挂引擎 LMDB 只读卷按键序扫描
       │                   scan → geo → emit(#444),产物写 /repo =
       │                   /opt/ip-radar-blocklist)
       └─ ExecStartPost: deploy/push.sh
                          (宿主机: commit → PAT 推 main,stderr 抹除 token)
```

**为什么生成与推送分离**:PAT(fine-grained,仅本仓 Contents RW)只存在于
宿主机 `/root/.config/blocklist-push.token`(0600)。容器只拿只读数据卷和
rw 仓目录,**token 永不进容器环境/compose 文件/镜像** —— 即便容器被攻破也
推不动仓库。compose 文件里因此没有任何 secret。

**#444 改版:导出不再调引擎查询接口**(2026-11-25):管线改按键序扫描
引擎 LMDB(scan → geo → emit,规格 docs/research/2026-11-24-blocklist-scan-
export-spec.md §5),全程只读库文件,引擎 API、原引擎查询 key
(IPRADAR_API_KEY)与配速(IPRADAR_REQUEST_INTERVAL_S)一并废除 ——
历史置备的 blocklist-engine.env 可删。前提:引擎镜像必须含 #444
(backend/ipdb/_scan.py);旧镜像在 scan 阶段报「引擎镜像早于 #444」
退出 1,先重建引擎镜像再跑。

## 安装步骤(root)

```bash
# 1. 克隆本仓(路径即 push.sh 的硬编码假定)
cd /opt && git clone https://github.com/steponeerror/ip-radar-blocklist.git ip-radar-blocklist

# 2. compose 配置自检(不启动任何容器;-q 静默通过即 OK)
cd /opt/ip-radar-blocklist
docker compose -f deploy/docker-compose.exporter.yml --profile export config -q

# 3. 核对引擎镜像含按键序扫描器(#444 A 步);没有就先部署引擎、重建镜像
docker run --rm --network none -w /app/backend --entrypoint python ipradar:latest \
  -c "import ipdb._scan; print('ok')"
#   (镜像的工作目录是 /app,引擎代码在 /app/backend,所以要 -w;导出器自己会把这个路径加进 sys.path)

# 4. 核对引擎数据卷存在且非空(默认假定 ip-lookup-tool_ipradar-data)
docker volume inspect ip-lookup-tool_ipradar-data --format '{{.Mountpoint}}'
#   必须存在 —— 导出器直接挂这个**命名卷**读 LMDB(不再猜宿主路径);
#   若引擎 compose 项目名不同,卷全名 = <项目名>_ipradar-data,
#   导出 IPRADAR_DATA_VOLUME=<实际卷名>(可写进 unit 的 Environment=)

# 5. 放置 PAT(0600,root;只在宿主机)
umask 077 && install -d /root/.config
cat > /root/.config/blocklist-push.token    # 粘贴 token,Ctrl-D
chmod 600 /root/.config/blocklist-push.token

# 6. 试跑一轮(生成 + 推送)
docker compose -f deploy/docker-compose.exporter.yml --profile export \
  run --rm blocklist-exporter && deploy/push.sh

# 7. 安装并启用 timer
cp deploy/ipradar-blocklist.service deploy/ipradar-blocklist.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ipradar-blocklist.timer
systemctl list-timers ipradar-blocklist.timer   # 核对下次触发点
```

手工触发一轮:`systemctl start ipradar-blocklist.service`;
日志(含 manifest JSON):`journalctl -u ipradar-blocklist.service -f`。

## 内存红线(为什么是 150m / restart "no")

- 服务器总内存 964Mi,常驻仅 ~124Mi 可用;引擎栈(ipradar + caddy)必须优先活。
- 容器 `mem_limit: 150m` 是 cgroup 硬顶,兜在管线自身 `--max-rss-mb 140`
  (匿名 RSS 自检、超限主动终止;自检口径见仓 README「内存红线与失败
  语义」)之外作机器保险:**fail-small —— 爆顶只死
  导出器,绝不拖垮引擎**。
- `restart: "no"`:一次性日任务。卡死的导出器自旋重启只会反复烧 CPU/内存;
  死了就等下一轮 timer。systemd 侧 `TimeoutStartSec=2h` 同理是守门,非预期
  运行时长。

## 可调环境变量(compose 插值)

| 变量 | 默认 | 用途 |
|---|---|---|
| `IPRADAR_DATA_VOLUME` | `ip-lookup-tool_ipradar-data` | 引擎栈的 LMDB 数据**命名卷**全名(`<引擎项目名>_ipradar-data`);导出器以只读方式挂到与引擎容器相同的 `/app/data`,不猜宿主路径 |

引擎代码与数据路径:导出器复用镜像 `ipradar:latest`,引擎 backend 直接用镜像
内烤入的 `/app/backend`(引擎 compose 从仓根 context 构建,baked 即权威版本,
不再从宿主 bind 覆盖 —— 与数据卷同理,消除路径猜测。

另:推送 token 可用 env `BLOCKLIST_PUSH_TOKEN` 临时覆盖 token 文件。

## 运维读 manifest.json

成功轮:`generated_at` / `tiers`(每档实际行数)/ `malicious_pool` /
`peak_rss_mb`(ru_maxrss 总量,仅观测)/ `peak_rss_anon_mb`(红线口径,
scan 阶段逐批采样与 geo 阶段采样两段的匿名内存最大值)/ `elapsed_s` / `stage_elapsed_s`(各阶段耗时)/
`asof`(判定时刻,两个阶段共用)/ `epochs`(扫描开跑时各库的纪元号)/
`scan_stats`(单元数、恶意数、读了几条记录)/ `geo_stats`(`looked_up` 补查了几个、
`verified` 逐列核对过的有几个、`drift_skipped` 只核对了一部分的有几个、
`drift_examples` 例子、`changed_sources` 扫描期间被重建过的源、这一段的匿名内存峰值)。
**失败轮:`error` 键出现即本轮失败**(带 `[阶段]` 前缀),此时 systemd 单元
为 failed、**未推送**;档位文件保持上一成功轮原样。处理:
`journalctl -u ipradar-blocklist.service` 看容器 stderr 进度行定位阶段,
修复后 `systemctl start ipradar-blocklist.service` 重跑。常见失败:
引擎数据卷缺失/为空(scan 阶段报「扫描出 0 个单元,不发空档位」——
空档位会被发成 Release,所以零单元直接停;看 `scan_stats.units_total`,
生产约 553 万,为 0 就是卷没挂对,修好卷再重跑)、引擎镜像太旧
(scan 阶段报「引擎镜像早于 #444」—— 先重建引擎镜像再跑)、geo 阶段
判定对不上(「geo 阶段判定核对失败」带例子的 IP 和列 —— 引擎扫描器与
查询接口行为不一致,按报错找引擎侧)、RSS 超限(看 `error` 里的阶段)、
token 失效(push 阶段,ExecStartPost)。

**扫描期间有源被重建(每轮都可能有,不是故障)**:生产上扫描要跑一个多小时,
期间引擎照常重建源(新纪元目录 + 换 ptr)。扫描读的是开跑时钉住的纪元,geo
核对调的查询接口读的是现在的纪元;重建恰好改了某个进榜地址的证据时,这个
地址的五列就对不上。核对规则:证据里有被重建过的源的地址,把被重建的源从
两边去掉再比(查询接口只算没重建的源),一致就跳过它、计入 `drift_skipped`;
其余地址逐列核对,对不上照样停。所以 `drift_skipped > 0` 且轮次成功是正常的,
`changed_sources` 里是这一轮被重建过的源。档位文件按扫描时的快照出。

## 残余风险(如实记录)

- 推送进行中的几秒,内嵌 token 的 URL 出现在 `git push` 进程 `/proc` cmdline
  (默认 Linux 对其他本机用户可读 root 进程 cmdline);单管理员机器已接受,
  详见 push.sh 内注释。stderr 抹除已改用 perl 从 `%ENV` 读 token(`\Q\E` 原样
  引用,凭据含正则元字符也安全),抹除器自身 argv 不再携带 token。
- `git config safe.directory` 仅在 git 拒绝时按需加入,且只加本仓路径。
