"""对外订阅质量门禁：少而稳。

只作用于 formats 输出的 4 种订阅，不裁剪 check_alive / veterans，
避免老兵池越缩越窄、后续 A 段无兵可复测。

默认策略（均可 env 覆盖）：
- LATENCY_MAX_MS=2000     延迟硬顶
- MAX_OUTPUT_NODES=60     订阅条数上限
- DEDUP_EXIT_IP=1         同出口 IP 只留延迟最优的 1 条
- DEDUP_CLUSTER=1         同质集群每组 1 条（IPv4: /24+port+proto；域名: host+port+proto）
- 分桶配额：避免 reality:443 垃圾全部 TopN；桶内按延迟，农场端口降权
- 不做亚洲硬配额、不做 MIN_VET_HITS
"""
import os
import re
from collections import defaultdict

LATENCY_MAX_MS = int(os.environ.get("LATENCY_MAX_MS", 2000))
MAX_OUTPUT_NODES = int(os.environ.get("MAX_OUTPUT_NODES", 60))
DEDUP_EXIT_IP = os.environ.get("DEDUP_EXIT_IP", "1") != "0"
DEDUP_CLUSTER = os.environ.get("DEDUP_CLUSTER", "1") != "0"

# 常见农场端口：只在排序时降权，不直接删除。
FARM_PORTS = {
    p.strip()
    for p in os.environ.get("FARM_PORTS", "8080,23576,8880").split(",")
    if p.strip()
}

# 分桶软上限（占 MAX 的比例）。第一轮按配额取，剩余名额按延迟从全部剩余补齐。
# 可被 BUCKET_QUOTAS=桶:数,桶:数 覆盖（绝对条数，会按 MAX 等比缩放）。
_BUCKET_ORDER = (
    "reality443",
    "vless_ws",
    "ss",
    "vmess",
    "reality_other",
    "other",
)
_DEFAULT_BUCKET_RATIOS = {
    "reality443": 0.50,
    "vless_ws": 0.20,
    "ss": 0.17,
    "vmess": 0.08,
    "reality_other": 0.05,
    "other": 0.00,
}

_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_SS_COMMON_PORTS = {"443", "80", "8388", "1234", "990"}


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


def bucket_of(n):
    """节点所属分桶（用于配额选拔）。"""
    port = _port(n)
    proto = _proto(n)
    net = _net(n)
    tls = _tls(n)
    if tls == "reality" and port == "443":
        return "reality443"
    if proto == "vless" and net in ("ws", "websocket"):
        return "vless_ws"
    if proto == "ss":
        return "ss"
    if proto == "vmess":
        return "vmess"
    if tls == "reality":
        return "reality_other"
    return "other"


def _parse_bucket_quotas(max_n):
    """返回 {bucket: cap}，cap 为软上限；总和可大于 max_n（由补齐逻辑收敛）。"""
    raw = os.environ.get("BUCKET_QUOTAS", "").strip()
    if raw:
        caps = {b: 0 for b in _BUCKET_ORDER}
        for part in raw.split(","):
            part = part.strip()
            if not part or ":" not in part:
                continue
            name, val = part.split(":", 1)
            name = name.strip()
            if name not in caps:
                continue
            try:
                caps[name] = max(0, int(val.strip()))
            except ValueError:
                continue
        total = sum(caps.values()) or 1
        # 按 MAX 等比缩放，避免用户按 60 写死后改 MAX 失效
        if total != max_n and max_n > 0:
            scaled = {k: int(v * max_n / total) for k, v in caps.items()}
            # 把四舍入误补到第一个非零桶
            drift = max_n - sum(scaled.values())
            for k in _BUCKET_ORDER:
                if scaled.get(k, 0) > 0 or caps.get(k, 0) > 0:
                    scaled[k] = scaled.get(k, 0) + drift
                    break
            caps = scaled
        return caps

    caps = {}
    assigned = 0
    items = list(_DEFAULT_BUCKET_RATIOS.items())
    for i, (name, ratio) in enumerate(items):
        if i == len(items) - 1:
            caps[name] = max(0, max_n - assigned)
        else:
            c = int(max_n * ratio)
            caps[name] = c
            assigned += c
    return caps


def _prefer_key(n):
    """去重/桶内排序：农场口靠后，延迟优先，SS 非常规口略优先。"""
    lat = _latency(n)
    lat = 999999 if lat is None else lat
    farm = 1 if _port(n) in FARM_PORTS else 0
    proto = _proto(n)
    port = _port(n)
    # SS：非常规非农场口优先于常见公开口
    ss_rank = 0
    if proto == "ss":
        if port in FARM_PORTS:
            ss_rank = 2
        elif port in _SS_COMMON_PORTS:
            ss_rank = 1
        else:
            ss_rank = 0
    no_exit = 0 if n.get("exit_ip") else 1
    dom = 0 if _is_domain(n.get("addr")) else 1
    return (farm, ss_rank, lat, no_exit, dom, str(n.get("key") or ""))


def _dedup(nodes, token_fn):
    """按 token 保序去重：先出现（已排序）的留下。"""
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


def _fill_by_buckets(nodes, max_n, quotas):
    """分桶配额填充，再用剩余候选按延迟补齐到 max_n。"""
    if max_n <= 0 or not nodes:
        return [], {b: 0 for b in _BUCKET_ORDER}, 0

    bins = defaultdict(list)
    for n in nodes:
        bins[bucket_of(n)].append(n)
    for b in bins:
        bins[b].sort(key=_prefer_key)

    picked = []
    used = set()
    picked_by = {b: 0 for b in _BUCKET_ORDER}

    for b in _BUCKET_ORDER:
        cap = max(0, int(quotas.get(b, 0)))
        if cap <= 0:
            continue
        for n in bins.get(b, []):
            if picked_by[b] >= cap:
                break
            k = n.get("key") or id(n)
            if k in used:
                continue
            picked.append(n)
            used.add(k)
            picked_by[b] += 1
            if len(picked) >= max_n:
                return picked, picked_by, 0

    # 剩余名额：全部未选中的按偏好度（延迟）补
    rest = []
    for b in _BUCKET_ORDER:
        for n in bins.get(b, []):
            k = n.get("key") or id(n)
            if k not in used:
                rest.append(n)
    # 也收未知桶名
    for b, lst in bins.items():
        if b in _BUCKET_ORDER:
            continue
        for n in lst:
            k = n.get("key") or id(n)
            if k not in used:
                rest.append(n)
    rest.sort(key=_prefer_key)
    fill = 0
    for n in rest:
        if len(picked) >= max_n:
            break
        picked.append(n)
        b = bucket_of(n)
        picked_by[b] = picked_by.get(b, 0) + 1
        fill += 1
    return picked, picked_by, fill


def select_stable(nodes):
    """筛选对外订阅节点。

    返回 (kept, stats)：
      kept  — 过滤/去重/分桶/截断后的节点列表
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

    # 先按延迟/农场降权排序，再去重（同组留更优）
    passed.sort(key=_prefer_key)
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

    after_dedup = after_dedup_cluster if DEDUP_CLUSTER else after_dedup_exit

    quotas = _parse_bucket_quotas(MAX_OUTPUT_NODES)
    # 候选池分桶规模（去重后）
    cand_by = {b: 0 for b in _BUCKET_ORDER}
    for n in passed:
        b = bucket_of(n)
        cand_by[b] = cand_by.get(b, 0) + 1

    kept, picked_by, fill_n = _fill_by_buckets(passed, max(0, MAX_OUTPUT_NODES), quotas)

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
        "bucket_quotas": {k: quotas.get(k, 0) for k in _BUCKET_ORDER},
        "bucket_candidates": {k: cand_by.get(k, 0) for k in _BUCKET_ORDER},
        "bucket_picked": {k: picked_by.get(k, 0) for k in _BUCKET_ORDER},
        "bucket_fill": fill_n,
    }
    return kept, stats
