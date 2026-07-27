"""按订阅源统计存活率，输出排序表 + output/source_stats.json。

归属口径：节点归给**首个收录它的源**（端点级去重后）。
所以「节点数」是该源的独有贡献，不是它解析出的总数 —— 被其他源先收录的
不会重复计入。这也意味着排序反映的是「独有节点的质量」，对后被处理的源
略有不利，但避免了一个节点被多个源重复统计。
"""
import json
import os
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent
TEMP = ROOT / "temp"
OUT = Path(os.environ.get("OUTPUT_DIR") or (ROOT.parent / "output"))


def main():
    pool_f, alive_f = TEMP / "nodes_all.json", TEMP / "alive.json"
    if not pool_f.exists():
        print("缺 temp/nodes_all.json，先跑 collect.py")
        return 1
    pool = json.loads(pool_f.read_text(encoding="utf-8"))
    alive = json.loads(alive_f.read_text(encoding="utf-8")) if alive_f.exists() else []

    # 存活节点靠 key 回查来源（alive.json 里已带 src_url，但旧数据可能没有）
    alive_keys = {n.get("key") for n in alive if n.get("key")}

    total, live, lat = defaultdict(int), defaultdict(int), defaultdict(list)
    pool_keys = set()
    for n in pool:
        s = n.get("src_url") or "(未记录)"
        total[s] += 1
        pool_keys.add(n.get("key"))
        if n.get("key") in alive_keys:
            live[s] += 1
    # 增量模式下老兵可能已从上游订阅里消失，但本轮仍测通。不补进来的话
    # 它的存活会凭空蒸发，源的存活率被低估。
    for n in alive:
        if n.get("key") and n["key"] not in pool_keys:
            s = n.get("src_url") or "(未记录)"
            total[s] += 1
            live[s] += 1
    for n in alive:
        s = n.get("src_url") or "(未记录)"
        if n.get("latency_ms"):
            lat[s].append(n["latency_ms"])

    rows = []
    for s, t in total.items():
        k = live[s]
        rows.append({
            "source": s,
            "nodes": t,
            "alive": k,
            "alive_rate": round(k / t * 100, 3) if t else 0.0,
            "avg_latency_ms": round(sum(lat[s]) / len(lat[s])) if lat[s] else None,
        })
    # 存活率降序；同率时存活数多的在前，再按节点数
    rows.sort(key=lambda r: (-r["alive_rate"], -r["alive"], -r["nodes"]))

    w = max(len(r["source"]) for r in rows) if rows else 10
    print(f"{'源':<{w}} {'节点数':>7} {'存活':>5} {'存活率':>8} {'均延迟':>8}")
    print("-" * (w + 32))
    for r in rows:
        ms = f"{r['avg_latency_ms']}ms" if r["avg_latency_ms"] else "-"
        rate = f"{r['alive_rate']:.3f}%" if r["alive"] else "0"
        print(f"{r['source']:<{w}} {r['nodes']:>7} {r['alive']:>5} {rate:>8} {ms:>8}")

    tn, tk = sum(total.values()), sum(live.values())
    print("-" * (w + 32))
    print(f"{'合计':<{w}} {tn:>7} {tk:>5} "
          f"{tk / tn * 100 if tn else 0:>7.3f}%")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "source_stats.json").write_text(
        json.dumps({"total_nodes": tn, "total_alive": tk, "sources": rows},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n-> {OUT / 'source_stats.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
