"""并发测活：经每个节点自己的 socks 端口请求 google/generate_204，判 204 + 延迟。

用 curl 而非 Python 的 socks 库，避免额外依赖（PySocks），且 curl 对
socks5h 的 DNS 远端解析支持更可靠。
"""
import json
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import veterans as vt
import xray_batch as xb

ROOT = Path(__file__).parent
TEMP = ROOT / "temp"

# 全部可由 workflow env / workflow_dispatch inputs 覆盖
# 并发默认值来自实测：批300/并发250 达 13.3 节点/秒，是批150/并发60 的 3 倍，
# 且命中数不变（无假阴性）。3 万节点的池必须靠这个速率才能压进 25 分钟超时。
TEST_URL = os.environ.get("TEST_URL", "https://www.google.com/generate_204")
TIMEOUT = int(os.environ.get("PROBE_TIMEOUT", 8))
RETRY = int(os.environ.get("PROBE_RETRY", 1))
WORKERS = int(os.environ.get("PROBE_WORKERS", 250))

TCP_TIMEOUT = int(os.environ.get("TCP_TIMEOUT", 4))
TCP_WORKERS = int(os.environ.get("TCP_WORKERS", 400))
# 分片：一次性把 3 万个 socket 丢给线程池会造成大量假阴性。
# 实测同样 5 个已知可达节点，1000 样本规模稳定检出 5/5，
# 但 3 万规模两次跑分别只检出 3/5 和 1/5，总可达数也在 7467~7608 间漂。
TCP_CHUNK = int(os.environ.get("TCP_CHUNK", 2000))
# 判定为不可达的再复查一轮，捞回因瞬时资源紧张而误杀的
TCP_RECHECK = int(os.environ.get("TCP_RECHECK", 1))

# 节点上限兜底：源突然暴涨时防止跑超 workflow 超时。0 = 不限。
# 超限时按轮次偏移抽样，而非固定截断前 N 个（否则后面的源永远测不到）。
MAX_NODES = int(os.environ.get("MAX_NODES", 0))
ROUND_SEED = int(os.environ.get("ROUND_SEED", 0))

# 增量模式：先复测上轮存活的「老兵」，再用剩余时间探索新节点。
# 关掉（INCREMENTAL=0）就是原来的全量重跑。
INCREMENTAL = os.environ.get("INCREMENTAL", "1") != "0"
# 实验模式：只复测 output/veterans.json，不探索普通候选池。
VET_ONLY = os.environ.get("VET_ONLY", "0") == "1"
# 实验模式：只取老兵，但强制走 B 段路径（TCP 预筛 -> Xray 批量测活）。
VET_B_PATH = os.environ.get("VET_B_PATH", "0") == "1"
# B 段（探索）的时间预算（秒）。到点就停在当前批次，把已测出的结果
# 交出去 —— 比被 workflow timeout 杀掉、整轮零产出好。0 = 不限。
BUDGET_SEC = int(os.environ.get("PROBE_BUDGET_SEC", 0))


def tcp_reachable(n, timeout=TCP_TIMEOUT):
    """握手前先探端口。公开池里约 88% 的节点服务器已死，
    先剔掉能省下绝大部分内核启动和 HTTP 测活开销。"""
    try:
        with socket.create_connection((n["addr"], int(n["port"])), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _scan(nodes, workers=None):
    """分片扫描，避免一次性建立数万 socket 造成假阴性"""
    workers = workers or TCP_WORKERS
    flags = []
    for i in range(0, len(nodes), TCP_CHUNK):
        chunk = nodes[i:i + TCP_CHUNK]
        with ThreadPoolExecutor(max_workers=workers) as ex:
            flags.extend(ex.map(tcp_reachable, chunk))
        time.sleep(0.2)  # 让内核回收上一片的 socket
    return flags


def prefilter_tcp(nodes):
    """TCP 预筛：分片扫描 + 对不可达者复查。

    实验（exp_tcp_filter.py）显示单轮扫描会误杀：2000 个被判不可达的节点里
    有 5 个实际能通 204，推算全池误杀约 55 个 —— 比一整轮测出的 42 个还多。
    根因不是超时太短（那些节点单独测握手仅 0.2-0.4s），而是大规模并发下的
    资源竞争。故分片 + 复查。
    """
    t0 = time.time()
    flags = _scan(nodes)
    kept = [n for n, ok in zip(nodes, flags) if ok]
    dead = [n for n, ok in zip(nodes, flags) if not ok]

    for r in range(TCP_RECHECK):
        if not dead:
            break
        # 复查用一半并发，进一步降低竞争
        again = _scan(dead, max(50, TCP_WORKERS // 2))
        back = [n for n, ok in zip(dead, again) if ok]
        dead = [n for n, ok in zip(dead, again) if not ok]
        if back:
            print(f"  复查第{r+1}轮捞回 {len(back)} 个（首轮误判为不可达）")
        kept.extend(back)

    print(f"TCP 预筛: {len(kept)}/{len(nodes)} 端口可达 "
          f"({len(kept)/max(len(nodes),1)*100:.1f}%)，耗时 {time.time()-t0:.0f}s\n")
    return kept


def probe(port, url=TEST_URL, timeout=TIMEOUT):
    """返回 (ok, latency_ms, http_code)。socks5h = 让代理端做 DNS 解析"""
    cmd = ["curl", "-s", "-o", os.devnull,
           "-w", "%{http_code} %{time_total}",
           "--socks5-hostname", f"127.0.0.1:{port}",
           "--max-time", str(timeout), url]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=timeout + 3)
        code, t = r.stdout.strip().split()
        return code == "204", int(float(t) * 1000), code
    except Exception:
        return False, 0, "000"


def probe_retry(port):
    for attempt in range(RETRY + 1):
        ok, ms, code = probe(port)
        if ok:
            return ok, ms, code
        if attempt < RETRY:
            time.sleep(0.2)
    return False, 0, code


def run_batch(nodes, batch_no, total_batches):
    """启动一批内核 → 并发测活 → 返回存活节点（含延迟）"""
    # 摘掉会让整份配置加载失败的节点（xray 26.x 移除了部分 transport）
    nodes = xb.drop_bad_outbounds(nodes, f"b{batch_no}")
    # 相邻批次错开端口段，避免上一批 TIME_WAIT 残留导致新进程启动失败
    base = xb.BASE_PORT + (batch_no % 3) * (xb.BATCH_SIZE + 20)
    cfg, mapping = xb.build_config(nodes, base_port=base)
    if not mapping:
        return []

    try:
        proc, _ = xb.start_xray(cfg, f"b{batch_no}")
    except RuntimeError as e:
        print(f"  批 {batch_no} 内核启动失败，跳过: {str(e)[:160]}")
        return []

    alive = []
    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            results = list(ex.map(lambda pn: probe_retry(pn[0]), mapping))
        for (port, n), (ok, ms, code) in zip(mapping, results):
            if ok:
                rec = dict(n)
                rec["latency_ms"] = ms
                alive.append(rec)
    finally:
        xb.stop_xray(proc)

    pct = len(alive) / len(mapping) * 100
    print(f"  批 {batch_no}/{total_batches}: 存活 {len(alive)}/{len(mapping)} ({pct:.1f}%)")
    return alive


def probe_nodes(nodes):
    """分批测活一组节点，返回存活列表"""
    batches = [nodes[i:i + xb.BATCH_SIZE]
               for i in range(0, len(nodes), xb.BATCH_SIZE)]
    alive = []
    for i, b in enumerate(batches, 1):
        alive.extend(run_batch(b, i, len(batches)))
    return alive


def main():
    nodes = json.loads((TEMP / "nodes_all.json").read_text(encoding="utf-8"))
    # 预先剔除 xray 无法构造的节点，避免整批配置加载失败
    nodes = [n for n in nodes if xb.to_outbound(n, "t") is not None]
    all_vets, _ = vt.load()
    all_vets = [n for n in all_vets if xb.to_outbound(n, "t") is not None]
    all_vet_keys = {n.get("key") for n in all_vets if n.get("key")}
    pool_vet_keys = {n.get("key") for n in nodes
                     if n.get("key") and n.get("key") in all_vet_keys}
    if VET_B_PATH:
        nodes = list(all_vets)
        pool_vet_keys = all_vet_keys

    t0 = time.time()
    pool_n = len(nodes)
    print(f"测活目标 {TEST_URL}，超时 {TIMEOUT}s，重试 {RETRY} 次")
    print(f"老兵诊断: 名单 {len(all_vets)} 个，本轮采集池命中 "
          f"{len(pool_vet_keys)} 个")
    if VET_B_PATH:
        print("[VET_B_PATH] 只取老兵，跳过 A 段，强制走 B 段批量测活")

    # ---------- A 段：先复测老兵 ----------
    # 上轮（及更早）测通过的节点跳过 TCP 预筛，直接测活。几十个节点
    # 一两批就跑完，几十秒内就有一份可用订阅垫底 —— 即使后面 B 段
    # 超时被 kill，也不会退化成空订阅。
    vet_alive, vet_tested = [], []
    if (INCREMENTAL or VET_ONLY) and not VET_B_PATH:
        vet_nodes = all_vets
        if vet_nodes:
            print(f"\n[A段] 复测老兵 {len(vet_nodes)} 个（跳过 TCP 预筛）")
            vet_tested = vet_nodes
            vet_alive = probe_nodes(vet_nodes)
            keep = len(vet_alive) / max(len(vet_nodes), 1) * 100
            print(f"[A段] 老兵存活 {len(vet_alive)}/{len(vet_nodes)} "
                  f"({keep:.1f}%)，耗时 {time.time() - t0:.0f}s")
            # 立刻落盘：BUDGET_SEC 只防「B 段自己超时」，防不住 runner 被
            # 硬 kill（网络卡死、内核挂住）。先写一份，那种情况下也还有订阅。
            if vet_alive:
                (TEMP / "alive.json").write_text(
                    json.dumps(sorted(vet_alive, key=lambda n: n["latency_ms"]),
                               ensure_ascii=False), encoding="utf-8")
        else:
            print("\n[A段] 老兵名单为空（首轮），跳过")

    if VET_ONLY:
        alive = sorted(vet_alive, key=lambda n: n["latency_ms"])
        out = TEMP / "alive.json"
        out.write_text(json.dumps(alive, ensure_ascii=False), encoding="utf-8")
        el = time.time() - t0
        print(f"\n[VET_ONLY] 老兵单独复测存活 {len(alive)}/{len(all_vets)}，"
              f"总耗时 {el/60:.1f} 分钟")
        print(f"-> {out}")
        return

    # ---------- B 段：探索新节点 ----------
    # 老兵已单独测过，从探索池里剔掉，别测两遍
    vet_keys = {n.get("key") for n in vet_tested if n.get("key")}
    if vet_keys:
        before = len(nodes)
        nodes = [n for n in nodes if n.get("key") not in vet_keys]
        print(f"[B段] 从探索池剔除老兵 {before - len(nodes)} 个")

    # 命令行参数优先（本地调试用），否则用 MAX_NODES
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else MAX_NODES
    if limit and len(nodes) > limit:
        # 轮次偏移抽样：每次从不同起点取一段，多轮滚动覆盖全池。
        # 固定截断前 N 个会让排在后面的源永远测不到。
        off = (ROUND_SEED * limit) % len(nodes)
        nodes = (nodes + nodes)[off:off + limit]
        print(f"候选池 {pool_n} 超过上限 {limit}，"
              f"本轮取 [{off}:{off + limit}]（ROUND_SEED={ROUND_SEED}）")

    total_in = len(nodes)
    b_vet_keys_before_tcp = {n.get("key") for n in nodes
                             if n.get("key") and n.get("key") in all_vet_keys}
    print(f"\n[B段] 探索候选 {total_in} 节点（已剔除老兵和 xray 不支持的）")
    nodes = prefilter_tcp(nodes)
    b_vet_keys_after_tcp = {n.get("key") for n in nodes
                            if n.get("key") and n.get("key") in all_vet_keys}
    if not INCREMENTAL:
        print(f"[B段诊断] 全量候选含老兵 {len(b_vet_keys_before_tcp)} 个，"
              f"TCP 预筛后剩 {len(b_vet_keys_after_tcp)} 个")

    batches = [nodes[i:i + xb.BATCH_SIZE]
               for i in range(0, len(nodes), xb.BATCH_SIZE)]
    print(f"[B段] 待测 {len(nodes)} 节点，分 {len(batches)} 批"
          f"（每批 {xb.BATCH_SIZE}）\n")
    new_alive, tested = [], list(vet_tested)
    for i, b in enumerate(batches, 1):
        # 时间预算：留出 formats/check_ip/提交的时间。超预算就停在
        # 当前批次，已测出的结果照常出订阅 —— 比被 timeout 杀掉、
        # 整轮零产出要好。
        if BUDGET_SEC and time.time() - t0 > BUDGET_SEC:
            print(f"  [B段] 已用 {(time.time()-t0)/60:.1f} 分钟，达时间预算 "
                  f"{BUDGET_SEC}s，剩余 {len(batches)-i+1} 批留给下一轮")
            break
        tested.extend(b)
        new_alive.extend(run_batch(b, i, len(batches)))

    # ---------- 合并 ----------
    # 老兵优先：同一 key 若两段都有（正常不会），保留 A 段结果
    merged, seen_keys = [], set()
    for n in vet_alive + new_alive:
        k = n.get("key")
        if k and k in seen_keys:
            continue
        if k:
            seen_keys.add(k)
        merged.append(n)
    alive = merged
    alive_vet_count = sum(1 for n in alive if n.get("key") in all_vet_keys)

    alive.sort(key=lambda n: n["latency_ms"])
    out = TEMP / "alive.json"
    out.write_text(json.dumps(alive, ensure_ascii=False), encoding="utf-8")

    if INCREMENTAL:
        kept, dropped = vt.update(alive, tested)
        print(f"\n老兵名单: {kept} 个（本轮淘汰 {dropped} 个，"
              f"连续 {vt.MISS_LIMIT} 轮未通即淘汰）")

    el = time.time() - t0
    print(f"\n存活 {len(alive)} 个 = 老兵 {len(vet_alive)} + 新发现 "
          f"{len(new_alive)}，总耗时 {el/60:.1f} 分钟")
    print(f"  诊断: 最终存活中老兵 {alive_vet_count} 个")
    print(f"  B段: 占 TCP可达 {len(nodes)} 的 "
          f"{len(new_alive)/max(len(nodes),1)*100:.1f}%，占候选 {total_in} 的 "
          f"{len(new_alive)/max(total_in,1)*100:.1f}%")
    if alive:
        lat = [n["latency_ms"] for n in alive]
        print(f"延迟 最快 {lat[0]}ms / 中位 {lat[len(lat)//2]}ms / 最慢 {lat[-1]}ms")
        print("\n最快 10 个:")
        for n in alive[:10]:
            print(f"  {n['latency_ms']:>5}ms  {n['proto']:<6} {n['addr']}:{n['port']}  {n['name'][:36]}")
    print(f"-> {out}")


if __name__ == "__main__":
    main()
