"""实验：TCP 预筛到底误杀了多少可用节点？

背景：check_alive.py 用 4 秒 TCP 握手超时把 75% 的节点挡在门外。
但跨境链路握手超过 4 秒很常见，这个预筛可能在丢真节点。

方法：抽 N 个被判「TCP 不可达」的节点，跳过预筛直接做真测活（google 204）。
若能测出存活，说明预筛超时过严。

只读，不改任何产物。
"""
import json
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import check_alive as ca
import xray_batch as xb

ROOT = Path(__file__).parent
TEMP = ROOT / "temp"
SAMPLE = int(os.environ.get("EXP_SAMPLE", 2000))
SEED = int(os.environ.get("EXP_SEED", 42))


def main():
    nodes = json.loads((TEMP / "nodes_all.json").read_text(encoding="utf-8"))
    nodes = [n for n in nodes if xb.to_outbound(n, "t") is not None]
    print(f"候选 {len(nodes)}（xray 可构造）")

    # 复现预筛：TCP_TIMEOUT 秒内握手成功即「可达」
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=ca.TCP_WORKERS) as ex:
        flags = list(ex.map(ca.tcp_reachable, nodes))
    reach = [n for n, ok in zip(nodes, flags) if ok]
    dead = [n for n, ok in zip(nodes, flags) if not ok]
    print(f"TCP 预筛({ca.TCP_TIMEOUT}s): 可达 {len(reach)} / 不可达 {len(dead)}"
          f"，耗时 {time.time()-t0:.0f}s\n")

    random.seed(SEED)
    sample = random.sample(dead, min(SAMPLE, len(dead)))
    print(f"从「不可达」里随机抽 {len(sample)} 个，跳过预筛直接测活")
    print(f"测活参数: {ca.TEST_URL} 超时 {ca.TIMEOUT}s 重试 {ca.RETRY} 次\n")

    t1 = time.time()
    alive, batches = [], [sample[i:i + xb.BATCH_SIZE]
                          for i in range(0, len(sample), xb.BATCH_SIZE)]
    for i, b in enumerate(batches, 1):
        alive.extend(ca.run_batch(b, i, len(batches)))

    el = time.time() - t1
    print(f"\n{'='*62}")
    print(f"结果：{len(sample)} 个「TCP 不可达」节点中，{len(alive)} 个实际能通 204")
    print(f"耗时 {el/60:.1f} 分钟")
    if alive:
        rate = len(alive) / len(sample)
        print(f"\n误杀率 {rate*100:.3f}% —— 推算全部 {len(dead)} 个被淘汰节点中")
        print(f"约有 {int(rate*len(dead))} 个是可用的，预筛超时应放宽。")
        print("\n捞回的节点：")
        for n in sorted(alive, key=lambda x: x["latency_ms"]):
            print(f"  {n['latency_ms']:>5}ms  {n['proto']:<7} "
                  f"{str(n['addr'])[:34]:<35} {str(n.get('name'))[:24]}")
    else:
        print("\n未捞回任何节点 —— 预筛的 4s 超时是合理的，"
              "被它淘汰的确实是死节点。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
