# deploy/ — 服务器部署资产(ip-radar-blocklist 每日导出)

服务器(demo,964Mi RAM)上的一键部署包:**容器生成、宿主机推送**。
本目录只交付资产;部署本身是操作人动作,按下述步骤执行。

## 运行形态

```
systemd timer (每日 04:30, Persistent=true)
  └─ ipradar-blocklist.service (Type=oneshot, root, idle 优先级)
       ├─ ExecStart:     docker compose run --rm blocklist-exporter
       │                  (容器: 走 LMDB 只读数据 + http://ipradar:8000 采样,
       │                   产物写 /repo = /opt/ip-radar-blocklist)
       └─ ExecStartPost: deploy/push.sh
                          (宿主机: commit → PAT 推 main,stderr 抹除 token)
```

**为什么生成与推送分离**:PAT(fine-grained,仅本仓 Contents RW)只存在于
宿主机 `/root/.config/blocklist-push.token`(0600)。容器只拿只读数据卷和
rw 仓目录,**token 永不进容器环境/compose 文件/镜像** —— 即便容器被攻破也
推不动仓库。compose 文件里因此没有任何 secret。

**引擎查询 key 是另一枚凭据,边界不同**(2026-10-03 final-review 裁定):引擎
查询端点(含 `POST /api/query/stream`)强制 Bearer key 鉴权,非同源程序化请求
无 key 即 401,故导出器必须带 key 调用 —— key 只能经 compose
`environment: IPRADAR_API_KEY: ${IPRADAR_API_KEY:-}` 透传**进容器**,即对
root 可见(`docker inspect` 能读容器 env)。这是已接受的边界:容器被攻破也
只多得一枚**可吊销的查询 key**(引擎 Admin UI 随时可删),推不动仓库;与
push PAT(永不进容器)形成对照。置备步骤见下第 5 步。

## 安装步骤(root)

```bash
# 1. 克隆本仓(路径即 push.sh 的硬编码假定)
cd /opt && git clone https://github.com/steponeerror/ip-radar-blocklist.git ip-radar-blocklist

# 2. compose 配置自检(不启动任何容器;-q 静默通过即 OK)
cd /opt/ip-radar-blocklist
docker compose -f deploy/docker-compose.exporter.yml --profile export config -q

# 3. 核对引擎 docker 网络名(默认假定 ip-lookup-tool_default)
docker network ls | grep ip-lookup-tool
#   若不同:导出 IPRADAR_NETWORK=<实际网络名>(可写进 unit 的 Environment=)

# 4. 核对引擎数据卷存在且非空(默认假定 ip-lookup-tool_ipradar-data)
docker volume inspect ip-lookup-tool_ipradar-data --format '{{.Mountpoint}}'
#   必须存在 —— 导出器直接挂这个**命名卷**读 LMDB(不再猜宿主路径);
#   若引擎 compose 项目名不同,卷全名 = <项目名>_ipradar-data,
#   导出 IPRADAR_DATA_VOLUME=<实际卷名>(可写进 unit 的 Environment=)

# 5. 置备引擎查询 key(0600,root;导出器调 /api/query/stream 用)
#    浏览器同源登录引擎 Admin UI(/admin)→ API Keys → 创建一枚给导出器用
#    的 key,然后宿主机落盘(env 文件形式,供 compose 插值):
umask 077 && install -d /root/.config
cat > /root/.config/blocklist-engine.env   # 写入一行:IPRADAR_API_KEY=<粘贴的 key>,Ctrl-D
chmod 600 /root/.config/blocklist-engine.env
#    timer 路径:systemd drop-in 把 env 文件喂给 unit(compose 在 ExecStart
#    进程内完成 ${IPRADAR_API_KEY:-} 插值):
systemctl edit ipradar-blocklist.service
#      [Service]
#      EnvironmentFile=/root/.config/blocklist-engine.env
#    (手工跑前则 shell 里 set -a; . /root/.config/blocklist-engine.env; set +a)
#    边界说明:这枚 key 经容器 env 传递,root 可 docker inspect 读到 ——
#    已接受(可吊销的查询凭据);push PAT 则永不进容器,见上文对照。

# 6. 放置 PAT(0600,root;只在宿主机)
umask 077 && install -d /root/.config
cat > /root/.config/blocklist-push.token    # 粘贴 token,Ctrl-D
chmod 600 /root/.config/blocklist-push.token

# 7. 试跑一轮(生成 + 推送;先带引擎 key)
set -a; . /root/.config/blocklist-engine.env; set +a
docker compose -f deploy/docker-compose.exporter.yml --profile export \
  run --rm blocklist-exporter && deploy/push.sh

# 8. 安装并启用 timer
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
| `IPRADAR_API_KEY` | _(空;不带 key 引擎即 401)_ | 引擎查询端点 Bearer 凭据;由 unit 的 `EnvironmentFile`(0600 env 文件)或手工 `export` 提供,compose 插值透传进容器。root 可经 `docker inspect` 读到 —— 已接受边界(可吊销查询凭据),与 push PAT(永不进容器)对照 |
| `IPRADAR_DATA_VOLUME` | `ip-lookup-tool_ipradar-data` | 引擎栈的 LMDB 数据**命名卷**全名(`<引擎项目名>_ipradar-data`);导出器以只读方式挂到与引擎容器相同的 `/app/data`,不猜宿主路径 |
| `IPRADAR_NETWORK` | `ip-lookup-tool_default` | 引擎 compose 项目网络 |

引擎代码与数据路径:导出器复用镜像 `ipradar:latest`,引擎 backend 直接用镜像
内烤入的 `/app/backend`(引擎 compose 从仓根 context 构建,baked 即权威版本,
已实机验证 import 走通),不再从宿主 bind 覆盖 —— 与数据卷同理,消除路径猜测。

另:推送 token 可用 env `BLOCKLIST_PUSH_TOKEN` 临时覆盖 token 文件。

## 运维读 manifest.json

成功轮:`generated_at` / `tiers`(每档实际行数)/ `malicious_pool` /
`peak_rss_mb`(ru_maxrss 总量,仅观测)/ `peak_rss_anon_mb`(红线口径) /
`elapsed_s` / `api_base`,以及 `walk_stats`、`enrich_stats`。
**失败轮:`error` 键出现即本轮失败**(带 `[阶段]` 前缀),此时 systemd 单元
为 failed、**未推送**;档位文件保持上一成功轮原样。处理:
`journalctl -u ipradar-blocklist.service` 看容器 stderr 进度行定位阶段,
修复后 `systemctl start ipradar-blocklist.service` 重跑。常见失败:
引擎未起/网络名不对(walk 前连通失败)、引擎 key 缺失/失效(enrich 阶段
401 永久中止 —— 核对 IPRADAR_API_KEY 与 Admin UI 里的 key 状态)、
RSS 超限(看 `error` 里的阶段)、token 失效(push 阶段,ExecStartPost)、引擎 503 warming(2 核机过载预热:客户端等 60s 重试同块,单轮至多 5 次才失败;配速已经 env `IPRADAR_REQUEST_INTERVAL_S=2.2` 放缓预防)。

另:开机补跑(Persistent=true)可能赶上引擎容器仍在 60s healthcheck
start_period 内 —— 首轮 walk 失败属预期,**下一轮 timer 会自愈**,勿慌张干预。

## 残余风险(如实记录)

- 推送进行中的几秒,内嵌 token 的 URL 出现在 `git push` 进程 `/proc` cmdline
  (默认 Linux 对其他本机用户可读 root 进程 cmdline);单管理员机器已接受,
  详见 push.sh 内注释。stderr 抹除已改用 perl 从 `%ENV` 读 token(`\Q\E` 原样
  引用,凭据含正则元字符也安全),抹除器自身 argv 不再携带 token。
- `git config safe.directory` 仅在 git 拒绝时按需加入,且只加本仓路径。
