"""对外订阅质量门禁：少而稳。

只作用于 formats 输出的 4 种订阅，不裁剪 check_alive / veterans，
避免老兵池越缩越窄、后续 A 段无兵可复测。

默认策略（均可 env 覆盖）：
- LATENCY_MAX_MS=2000     延迟硬顶
- MAX_OUTPUT_NODES=60     订阅条数上限
- DEDUP_EXIT_IP=1         同出口 IP 只留结构分+延迟最优的 1 条
- DEDUP_CLUSTER=1         同质集群每组 1 条（IPv4: /24+port+proto；域名: host+port+proto）
- 结构排序：reality:443 / vless+ws / 域名 优先；8080/23576/8880 等农场端口降权
- 不做亚洲硬配额、不做 MIN_VET_HITS（对照真连样本后明确放弃）
"""
import os
import re

LATENCY_MAX_MS = int(os.environ.get("LATENCY_MAX_MS", 2000))
MAX_OUTPUT_NODES = int(os.environ.get("MAX_OUTPUT_NODES", 60))
DEDUP_EXIT_IP = os.environ.get("DEDUP_EXIT_IP", "1") != "0"
DEDUP_CLUSTER = os.environ.get("DEDUP_CLUSTER", "1") != "0"

# 常见农场端口：只在排序时降权，不直接删除。
# 对照真连样本后保留「结构提权 + 农场降权」比硬删更稳。
FARM_PORTS = {
    p.strip()
    for p in os.environ.get("FARM_PORTS", "8080,23576,8880").split(",")
    if p.strip()
}

_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _latency(n):
    v = n.get("latency_ms")
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _is_ipv4(addr):
    m = _IPV4.match(str(addr or ""))
    if not m:
        return False
    try:
        return all(0 <= int(x) <= 255 for x in m.groups())
    except ValueError:
        return False


def _is_domain(addr):
    a = str(addr or "")
    return bool(a) and not _is_ipv4(a) and any(c.isalpha() for c in a)


def _port(n):
    return str(n.get("port") or "")


def _net(n):
    return str(n.get("net") or "tcp").lower()


def _tls(n):
    return str(n.get("tls") or "").lower()


def _proto(n):
    return str(n.get("proto") or "").lower()


def cluster_key(n):
    """同质集群键：IP 用 /24+port+proto，域名用 host+port+proto。"""
    addr = str(n.get("addr") or "").strip()
    port = _port(n)
    proto = _proto(n) or "unknown"
    if _is_ipv4(addr):
        a, b, c, _d = addr.split(".")
        return f"{a}.{b}.{c}|{port}|{proto}"
    return f"host:{(addr or '?').lower()}|{port}|{proto}"


def _structure_rank(n):
    """结构分：越小越优先。

    对照本地真连 7 样本与整份订阅 100 条后的排序启发：
    优先 reality:443 / 域名 / 非常规端口；农场端口与常见 hits 农场降权。
    """
    port = _port(n)
    proto = _proto(n)
    net = _net(n)
    tls = _tls(n)
    farm = 1 if port in FARM_PORTS else 0

    if tls == "reality" and port == "443":
        tier = 0
    elif proto == "vless" and net in ("ws", "websocket"):
        tier = 1
    elif _is_domain(n.get("addr")):
        tier = 2
    elif tls == "reality":
        tier = 3
    elif proto == "vless":
        tier = 4
    elif proto == "ss" and port not in FARM_PORTS:
        # 非常规端口 SS 往往比常见公开口更稳（如 :10210）。
        # 常见 443/80/8388/1234 等公开 SS 口降到更后。
        if port not in {"443", "80", "8388", "1234", "990"}:
            tier = 2
        else:
            tier = 5
    elif proto == "vmess":
        tier = 6
    else:
        tier = 7

    # 同 tier 时域名略优先
    dom = 0 if _is_domain(n.get("addr")) else 1
    return (farm, tier, dom)


def _sort_key(n):
    lat = _latency(n)
    lat = 999999 if lat is None else lat
    no_exit = 0 if n.get("exit_ip") else 1
    return (*_structure_rank(n), lat, no_exit, str(n.get("key") or ""))


def _dedup(nodes, token_fn):
    """按 token 保序去重：先出现（已按结构分+延迟排好）的留下。"""
    seen = set()
    kept = []
    drop = 0
    for n in nodes:
        token = token_fn(n)
        if token in seen:
            drop += 1
            continue
        seen.add(token)
        kept.append(n)
    return kept, drop


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

    # 先按结构分+延迟排序，再去重，保证留下的是更优那条
    passed.sort(key=_sort_key)
    after_latency = len(passed)

    drop_dup_exit = 0
    if DEDUP_EXIT_IP:
        def exit_token(n):
            ip = n.get("exit_ip")
            if ip:
                return f"ip:{ip}"
            return f"key:{n.get('key') or id(n)}"

        passed, drop_dup_exit = _dedup(passed, exit_token)
    after_dedup_exit = len(passed)

    drop_dup_cluster = 0
    if DEDUP_CLUSTER:
        passed, drop_dup_cluster = _dedup(passed, cluster_key)
    after_dedup_cluster = len(passed)

    # 兼容旧字段 after_dedup：表示出口+集群去重后的最终候选数
    after_dedup = after_dedup_cluster if DEDUP_CLUSTER else after_dedup_exit

    kept = passed[: max(0, MAX_OUTPUT_NODES)]
    stats = {
        "alive_raw": raw_n,
        "after_latency": after_latency,
        "after_dedup_exit": after_dedup_exit,
        "after_dedup_cluster": after_dedup_cluster,
        "after_dedup": after_dedup,
        "alive_output": len(kept),
        "drop_no_latency": drop_no_lat,
        "drop_slow": drop_slow,
        "drop_dup_exit": drop_dup_exit,
        "drop_dup_cluster": drop_dup_cluster,
        "latency_max_ms": LATENCY_MAX_MS,
        "max_output_nodes": MAX_OUTPUT_NODES,
        "dedup_exit_ip": DEDUP_EXIT_IP,
        "dedup_cluster": DEDUP_CLUSTER,
        "farm_ports": sorted(FARM_PORTS),
    }
    return kept, stats
