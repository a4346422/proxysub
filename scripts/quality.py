"""对外订阅质量门禁：少而稳。

只作用于 formats 输出的 4 种订阅，不裁剪 check_alive / veterans，
避免老兵池越缩越窄、后续 A 段无兵可复测。

默认策略（均可 env 覆盖）：
- LATENCY_MAX_MS=2000  延迟硬顶
- MAX_OUTPUT_NODES=100 订阅条数上限
- DEDUP_EXIT_IP=1      同出口 IP 只留延迟最低的 1 条
- 无 exit_ip 的节点保留，用 key 去重，排序靠后于「有出口且延迟更优」者
  （由延迟排序自然体现；同延迟时亚洲出口略优先）
"""
import os

LATENCY_MAX_MS = int(os.environ.get("LATENCY_MAX_MS", 2000))
MAX_OUTPUT_NODES = int(os.environ.get("MAX_OUTPUT_NODES", 100))
DEDUP_EXIT_IP = os.environ.get("DEDUP_EXIT_IP", "1") != "0"

# 仅影响截断前的挑选顺序，不按国家删除
ASIA_BOOST = {"HK", "JP", "SG", "KR", "TW", "MO", "TH", "MY"}


def _latency(n):
    v = n.get("latency_ms")
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _sort_key(n):
    lat = _latency(n)
    lat = 999999 if lat is None else lat
    cc = (n.get("country_code") or "").upper()
    asia = 0 if cc in ASIA_BOOST else 1
    # 有出口信息的略优先，便于 100 名额里多留可标注节点
    no_exit = 0 if n.get("exit_ip") else 1
    return (lat, asia, no_exit, str(n.get("key") or ""))


def select_stable(nodes):
    """筛选对外订阅节点。

    返回 (kept, stats)：
      kept  — 过滤/去重/截断后的节点列表
      stats — 供 status.json 记录的过程计数与参数
    """
    raw = list(nodes or [])
    raw_n = len(raw)

    passed = []
    drop_no_lat = drop_slow = 0
    for n in raw:
        lat = _latency(n)
        if lat is None:
            drop_no_lat += 1
            continue
        if lat > LATENCY_MAX_MS:
            drop_slow += 1
            continue
        passed.append(n)

    passed.sort(key=_sort_key)
    after_latency = len(passed)

    drop_dup = 0
    if DEDUP_EXIT_IP:
        seen = set()
        deduped = []
        for n in passed:
            ip = n.get("exit_ip")
            token = f"ip:{ip}" if ip else f"key:{n.get('key') or id(n)}"
            if token in seen:
                drop_dup += 1
                continue
            seen.add(token)
            deduped.append(n)
        passed = deduped
    after_dedup = len(passed)

    kept = passed[: max(0, MAX_OUTPUT_NODES)]
    stats = {
        "alive_raw": raw_n,
        "after_latency": after_latency,
        "after_dedup": after_dedup,
        "alive_output": len(kept),
        "drop_no_latency": drop_no_lat,
        "drop_slow": drop_slow,
        "drop_dup_exit": drop_dup,
        "latency_max_ms": LATENCY_MAX_MS,
        "max_output_nodes": MAX_OUTPUT_NODES,
        "dedup_exit_ip": DEDUP_EXIT_IP,
    }
    return kept, stats
