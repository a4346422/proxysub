"""累积各源的历史存活统计，供删源决策使用。

为什么需要：单轮存活总数只有 20-30 个，一个只有 5 个节点的源本来就极可能
测不出存活。仅凭单轮的「存活 0」删源会误杀 —— 必须看多轮累积。

每轮把 source_stats.json 合并进 output/source_history.json，记录：
  rounds        该源参与过的轮数
  zero_rounds   其中存活为 0 的轮数
  nodes_last    最近一轮的节点数
  alive_total   历轮存活累计
判定「可删」的条件是 zero_rounds >= MIN_ROUNDS_TO_JUDGE 且 alive_total == 0。
"""
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).parent
OUT = Path(os.environ.get("OUTPUT_DIR") or (ROOT.parent / "output"))
# 至少这么多轮都为 0 才建议删除
MIN_ROUNDS = int(os.environ.get("MIN_ROUNDS_TO_JUDGE", 10))


def main():
    cur_f = OUT / "source_stats.json"
    if not cur_f.exists():
        print("缺 output/source_stats.json，先跑 src_stats.py")
        return 1
    cur = json.loads(cur_f.read_text(encoding="utf-8"))

    hist_f = OUT / "source_history.json"
    hist = (json.loads(hist_f.read_text(encoding="utf-8"))
            if hist_f.exists() else {"rounds": 0, "sources": {}})

    hist["rounds"] = hist.get("rounds", 0) + 1
    hist["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    src = hist.setdefault("sources", {})

    for r in cur.get("sources", []):
        e = src.setdefault(r["source"], {"rounds": 0, "zero_rounds": 0,
                                        "alive_total": 0, "nodes_total": 0,
                                        "nodes_last": 0})
        e["rounds"] += 1
        e["nodes_last"] = r["nodes"]
        e["nodes_total"] = e.get("nodes_total", 0) + r["nodes"]
        e["alive_total"] += r["alive"]
        if r["alive"] == 0:
            e["zero_rounds"] += 1
        # 分母用历轮节点数之和，而非最近一轮 —— 否则多轮累积的存活数
        # 除以单轮节点数会虚高
        e["alive_rate_cum"] = round(
            e["alive_total"] / max(e["nodes_total"], 1) * 100, 4)

    hist_f.write_text(json.dumps(hist, ensure_ascii=False, indent=2),
                      encoding="utf-8")

    rows = sorted(src.items(),
                  key=lambda kv: (-kv[1]["alive_total"], -kv[1]["nodes_last"]))
    print(f"累计 {hist['rounds']} 轮\n")
    print(f"{'源':<58} {'节点':>6} {'累计存活':>8} {'轮数':>5} {'零轮':>5}")
    print("-" * 86)
    for name, e in rows:
        print(f"{name[:57]:<58} {e['nodes_last']:>6} {e['alive_total']:>8} "
              f"{e['rounds']:>5} {e['zero_rounds']:>5}")

    dead = [(n, e) for n, e in rows
            if e["alive_total"] == 0 and e["rounds"] >= MIN_ROUNDS]
    pending = [(n, e) for n, e in rows
               if e["alive_total"] == 0 and e["rounds"] < MIN_ROUNDS]

    print()
    if dead:
        print(f"建议删除（连续 {MIN_ROUNDS}+ 轮零存活）：")
        for n, e in dead:
            print(f"  {n}  ({e['nodes_last']} 节点, {e['rounds']} 轮全零)")
    if pending:
        print(f"数据不足，暂不判定（需满 {MIN_ROUNDS} 轮）：{len(pending)} 个源")
        for n, e in pending[:5]:
            print(f"  {n}  (才 {e['rounds']} 轮)")
    if not dead and not pending:
        print("所有源都有存活产出。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
