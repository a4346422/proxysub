# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 这是什么

采集公开免费代理订阅源 → 解析成统一节点结构 → 用真实 Xray 内核测活 → 输出 4 种订阅格式。
部署在 GitHub Actions 上每小时自动跑一轮，结果提交回仓库当订阅地址用。

**两份代码，别混淆：**

| 目录 | 状态 | 说明 |
|---|---|---|
| 根目录 | **交付物，改这里** | Linux/CI 可跑的完整流程，含增量调度、出口 IP 查询、源统计 |

主要流程代码在 `scripts/` 下，GitHub Actions workflow 在 `.github/workflows/` 下。

## 常用命令

全部命令在 `scripts/` 下执行。Windows 上必须带 `PYTHONIOENCODING=utf-8`，否则中文输出会抛 `UnicodeDecodeError`。

```bash
# 本地跑单个阶段（顺序有依赖：collect → check_alive → check_ip → formats）
PYTHONIOENCODING=utf-8 python collect.py                    # → temp/nodes_all.json
PYTHONIOENCODING=utf-8 XRAY_BIN="D:/GFW/v2rayN-windows-64/bin/xray/xray.exe" \
  python check_alive.py                                     # → temp/alive.json
PYTHONIOENCODING=utf-8 XRAY_BIN="..." python check_ip.py    # 回写出口 IP/国家
PYTHONIOENCODING=utf-8 python formats.py                    # → output/ 4 种格式
PYTHONIOENCODING=utf-8 python src_stats.py                  # 本轮源存活率
PYTHONIOENCODING=utf-8 python src_history.py                # 多轮累积

# 只测少量节点（B 段限量，本地调试必用 —— 全量一轮 30+ 分钟）
python check_alive.py 3000

# 强制全量重跑（关掉增量调度）
INCREMENTAL=0 python check_alive.py

# TCP 预筛误杀率实验：从「不可达」里抽样跳过预筛直接测活
EXP_SAMPLE=2000 python exp_tcp_filter.py
```

没有测试框架、没有 lint 配置、不是 git 仓库。**验证靠实跑**：改完 `check_alive.py` 就带 `3000` 参数跑一轮，改完 `formats.py` 就解 base64 / `yaml.safe_load` / `json.load` 校验四种输出的条数和名称唯一性。

`XRAY_BIN` 不设时默认找 `bin/xray`（CI 里由 workflow 下载解压）。本地没有就指向 v2rayN 自带的内核。

## 架构要点

### 一次启核测 N 个节点

`xray_batch.py` 是整个流程的基础设施。它生成一份含 N 个 socks 入站 + N 个出站的 Xray 配置，用 routing rule 把 `inN` 绑到 `outN`，于是**一次启核就能并发探测 100 个节点**（默认 `BATCH_SIZE=100`），避免几万次内核启停。测活时 `curl --socks5-hostname 127.0.0.1:<port>` 打哪个端口就是在测哪个节点。

这个设计有个致命脆弱点：**一个非法出站会让整份配置加载失败，整批节点全部误报为 0 存活**。曾因单个 h2 节点导致 8 个批次连续全灭。防护是两层，改 `xray_batch.py` 时不要动：

- `config_ok()` 用 `xray -test` 预校验，`drop_bad_outbounds()` 解析报错里的 `tag outN` 定位并摘掉肇事节点。注意 `outN` 的 N 是 mapping 下标，**必须映射回实际节点对象再按身份过滤**，按列表下标删会因删除后位移而误删好节点。
- `SS_CIPHERS` 白名单（xray 已移除 CFB/CTR/RC4）、`_stream_settings()` 对 `net in ("h2","http")` 返回 `None`（Xray 26.x 移除了 h2 transport，迁到 XHTTP）。返回 `None` 后调用方必须一并返回 `None`，否则节点会静默退化成明文 TCP 产生假结果。

批次间要 `wait_ports_free()` 并错开端口段（`base = BASE_PORT + (batch_no % 3) * (BATCH_SIZE + 20)`），否则 TIME_WAIT 残留会让新进程静默启动失败，而 `port_ready()` 又把旧监听误认成"已就绪"。

### 增量调度（A/B 两段）

`check_alive.py` 的核心设计。原来每轮把 3 万节点从头重跑 40 分钟，而结果和上轮高度重叠。

- **A 段**：读 `output/veterans.json`（老兵名单 = 历史测通过的节点），跳过 TCP 预筛直接测活。约 70 个节点 17 秒跑完，**结果立刻落盘** —— 这样即使 B 段被 runner 硬 kill，这轮也有可用订阅。
- **B 段**：从池子里剔掉老兵后走常规流程（TCP 预筛 → 分批测活），受 `PROBE_BUDGET_SEC`（默认 1920s）约束，到点停在当前批次，剩余批次留给下一轮。

`veterans.py` 维护名单。三个约束不要改：

1. 存在 `output/` 下才能被 workflow 的 `git add output/` 提交，这是它跨轮存活的**唯一途径**（runner 每轮都是新容器）
2. 瘦身用**黑名单**（`DROP` 只剔 `latency_ms`/`idx`），不用白名单。曾用白名单漏掉 ss 的 `method` 字段，导致节点静默变成不可构造
3. 国家/出口 IP **保留**在名单里。`check_ip.py` 是 `continue-on-error`，它失败时若无缓存，整份订阅节点名会退化成 UNKNOWN
4. 淘汰要连续 `VET_MISS_LIMIT`（默认 3）轮未通；本轮没测到的老兵**不扣分**，否则 B 段被预算截断时会误伤

### TCP 预筛必须分片 + 复查

`prefilter_tcp()` 里的 `TCP_CHUNK=2000` 和 `TCP_RECHECK=1` 不是调参，是修 bug。一次性把 3 万个 socket 丢给线程池会产生大规模假阴性：同样 5 个已知可达节点，1000 样本规模稳定检出 5/5，3 万规模两次跑只检出 3/5 和 1/5。`exp_tcp_filter.py` 量化过误杀率 0.25%，全池约 55 个可用节点被误杀 —— 比一整轮测出的 42 个还多。分片 + 复查后可达数从 7.5k 升到 16k。

根因是并发资源竞争，不是超时太短（那些节点单独测握手只要 0.2–0.4 秒）。**不要试图用调高并发来加速** —— 实测 250/400/500 三档吞吐相同（约 9 节点/秒），已饱和。

### 两层去重

`collect.py` 里凭证级（`proto|addr|port|cred`）→ 端点级（`proto|addr|port`）。公开池里大量节点是同一入口配几百个不同 UUID（实测单端点被复用 602 次），测活结果必然相同。这层把 4.2 万压到 3 万。

指纹存在节点的 `key` 字段 —— **不能用 `fp`**，那是 TLS utls fingerprint 字段。

上游字段类型很脏（`tls` 可能是 bool、`port` 可能是 str），统一用 `_s()` 取字符串、`int(n["port"])` 兜底。

### 节点命名

节点名**只保留实测出口的国家码 + 国家名 + 同国编号**（`US 美国1`、`TR 土耳其1`），上游原名全部丢弃 —— 因为原名的国家标注大量不实（实测"荷兰"出口在美国、"香港"在土耳其）。`check_ip.py` 经节点自身的 socks 端口查 ip-api/ipinfo 拿真实落地。输出排序按 HK/JP/SG/US 优先，其余国家按国家码排序，未知国家最后；同国家内按上游节点名排序后编号。编号本身即保证 Clash/sing-box 要求的名称唯一。查询失败记 `UNKNOWN`，不猜测。

`check_ip.py` 的 `IP_WORKERS` 默认 3 而非更高：查询走节点自身带宽，并发 6 时 7/19 查不到，降到 3 后 15/19。

### 源管理

`sources.txt` 一行一个 URL，Clash YAML 类型在 URL 后加 ` clash`。改源不用动代码。URL 里可用 `{YMD}`/`{Y}`/`{m}`/`{d}` 占位符处理按日期滚动命名的源。

**删源判定标准（`sources.txt` 头部有完整说明，改动前先读）**：绝不凭单轮"存活 0"删源。单轮存活总数只有 20–40 个，几十节点的源本来就极可能测不出存活。实例：`mahdibland/V2RayAggregator`（4604 节点，池子第二大）第 1 轮零存活第 2 轮出 1 个，按单轮删会误杀。正确做法是看 `output/source_history.json` 的多轮累积，满 `MIN_ROUNDS_TO_JUDGE`（默认 10）轮仍为 0 才考虑。

采集日志里的 `+0` 也**不代表该源无用** —— 同仓库的链接式版本先被收录时，其 Clash 版本就会显示 `+0` 但仍可能有独有端点。判断真冗余要看端点差集（README 有现成命令）。

`src_stats.py` 的归属口径：节点归给**首个收录它的源**，所以"节点数"是独有贡献而非解析总数。

## 关键环境变量

完整表在 `README.md`。最常用于本地调试的：

| 变量 | 默认 | 作用 |
|---|---|---|
| `XRAY_BIN` | `bin/xray` | 内核路径 |
| `INCREMENTAL` | 1 | 增量调度，设 0 全量重跑 |
| `PROBE_BUDGET_SEC` | 1920 | B 段时间预算，0 = 不限 |
| `MAX_NODES` | 32000 | 候选池上限，超出按 `ROUND_SEED` 偏移抽样 |
| `CHECK_IP` | 1 | 设 0 跳过出口 IP 查询，省 1–2 分钟 |
| `TCP_CHUNK` / `TCP_RECHECK` | 2000 / 1 | 见上文，不要随意改 |

## 踩过的坑

- **subprocess 必须显式 `encoding="utf-8", errors="replace"`**。`text=True` 单独用会在非 ASCII 字节上抛 `UnicodeDecodeError`，静默丢结果。
- **读 `status.json` 必须显式 encoding**。workflow 的 sanity 检查曾因此取到空值 → 数值比较报错 → 空订阅保护逻辑被完全跳过。现在有 `-ge 0` 有效性闸门兜底。
- **Git Bash 的 `/tmp/x` 和 Python 看到的路径不是一回事**，用仓库相对路径。
- **别用 `nohup ... &` 后台跑长任务**，进程会随 Bash 调用结束被杀，只留 0 字节日志。用 harness 自己的 backgrounding。

## 已知局限（不是 bug）

可用率就是很低：3 万节点测出几十个（约 0.2%）。公开池里约 70% 服务器端口已死，剩下多数也无法真正出墙。池子从 5550 涨到 30271（5.5 倍）而存活数仍在 19–65 区间 —— 多数源在循环回收同一批死节点。节点寿命也极短，复测时几分钟内就有掉线的。

不支持 hysteria2 / tuic / ssr / 老式 ss 加密，采集阶段直接丢弃。
