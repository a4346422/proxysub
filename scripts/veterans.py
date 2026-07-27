"""老兵名单：跨轮持久化「曾经测活成功」的节点，让每轮先复测它们。

为什么要这个：原来每轮都把 3 万个节点从 TCP 预筛开始重跑，40 分钟后
才知道存活集 —— 而这个集合和上一轮高度重叠（同一批机器不会一小时就
全换掉）。上轮存活的 65 个节点没有任何优待，和 3 万个死节点一起排队。

改成两段式后：
  A 段 复测老兵 —— 几十个节点，跳过 TCP 预筛直接测活，约 30 秒出结果
  B 段 探索新节点 —— 用剩下的时间预算跑常规流程，发现新的存活

老兵名单存在 output/veterans.json（跟着仓库提交，所以能跨 Actions 轮次
存活；runner 每轮都是全新容器，本地文件保不住）。

淘汰规则：连续 MISS_LIMIT 轮没测通就移出名单。不用「一次没通就删」——
免费节点抖动很大，本轮 timeout 下轮又活是常态。
"""
import json
import os
from pathlib import Path

ROOT = Path(__file__).parent
# 存在 output/ 下才会被 workflow 的 git add output/ 带上，从而跨轮保留
OUT = Path(os.environ.get("OUTPUT_DIR") or (ROOT.parent / "output"))
VET_FILE = OUT / "veterans.json"

# 连续多少轮测不通就淘汰。免费节点单轮抖动大，给 3 轮宽限。
MISS_LIMIT = int(os.environ.get("VET_MISS_LIMIT", 3))
# 名单上限，防止无限膨胀吃掉 A 段时间。按存活数量级 65 给 4 倍余量。
MAX_VET = int(os.environ.get("VET_MAX", 400))

# 需要持久化的字段：够 xray 重建 outbound + 溯源 + 展示
# 不存 latency_ms/exit_ip 之类每轮会变的，那些由当轮实测覆盖
# 用黑名单而非白名单：协议字段太多（vmess 的 aid/scy、ss 的 method、
# vless 的 flow/pbk/sid…），白名单漏一个就让节点静默变成不可构造。
# 只剔除「每轮都会变、存了会误导」的字段。
#
# 出口 IP / 国家**保留**：check_ip 步骤是 continue-on-error，它失败时
# 若没有缓存，整份订阅的节点名会退化成 UNKNOWN。同一台机器的落地国家
# 基本不变，用上轮的值兜底远好过没有。check_ip 成功时会覆盖掉。
DROP = ("latency_ms", "idx")


def _slim(n):
    return {k: v for k, v in n.items() if k not in DROP}


def load():
    """→ (nodes, meta)。meta 是 key → {miss, hits, rounds}"""
    if not VET_FILE.exists():
        return [], {}
    try:
        d = json.loads(VET_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        # 名单损坏不该让整轮失败，退化成纯探索模式即可
        print(f"  老兵名单读取失败（{str(e)[:40]}），本轮按无名单处理")
        return [], {}
    return d.get("nodes", []), d.get("meta", {})


def save(nodes, meta):
    OUT.mkdir(parents=True, exist_ok=True)
    VET_FILE.write_text(json.dumps(
        {"count": len(nodes), "nodes": nodes, "meta": meta},
        ensure_ascii=False), encoding="utf-8")


def update(alive, tested):
    """用本轮结果更新名单。

    alive  —— 本轮测通的节点（含新发现的）
    tested —— 本轮实际测过的节点，只有测过的才算「miss 一次」；
              没排到队的老兵不能因为没测就被扣分
    """
    old_nodes, meta = load()
    by_key = {n.get("key"): n for n in old_nodes if n.get("key")}

    alive_keys = {n.get("key") for n in alive if n.get("key")}
    tested_keys = {n.get("key") for n in tested if n.get("key")}

    for n in alive:
        k = n.get("key")
        if not k:
            continue
        by_key[k] = _slim(n)
        m = meta.setdefault(k, {"miss": 0, "hits": 0, "rounds": 0})
        m["miss"] = 0
        m["hits"] = m.get("hits", 0) + 1
        m["rounds"] = m.get("rounds", 0) + 1

    dropped = 0
    for k in list(by_key):
        if k in alive_keys:
            continue
        if k not in tested_keys:
            continue  # 本轮没测到，不扣分
        m = meta.setdefault(k, {"miss": 0, "hits": 0, "rounds": 0})
        m["miss"] = m.get("miss", 0) + 1
        m["rounds"] = m.get("rounds", 0) + 1
        if m["miss"] >= MISS_LIMIT:
            del by_key[k]
            meta.pop(k, None)
            dropped += 1

    # 超限时保留命中次数多、miss 少的（长期稳定的机器优先）
    nodes = list(by_key.values())
    if len(nodes) > MAX_VET:
        def score(n):
            m = meta.get(n.get("key"), {})
            return (-m.get("hits", 0), m.get("miss", 0))
        nodes.sort(key=score)
        keep_keys = {n.get("key") for n in nodes[:MAX_VET]}
        meta = {k: v for k, v in meta.items() if k in keep_keys}
        nodes = nodes[:MAX_VET]

    save(nodes, meta)
    return len(nodes), dropped
