"""输出 GitHub Actions Step Summary（Markdown）。

单独成脚本而非内联 heredoc —— workflow 的 shell 里嵌套 heredoc 很脆弱。
"""
import json
import os
from pathlib import Path

OUT = Path(os.environ.get("OUTPUT_DIR")
           or (Path(__file__).parent.parent / "output"))


def main():
    print("### 订阅更新结果\n")
    f = OUT / "status.json"
    if not f.exists():
        print("未产出 `status.json` —— 流程在出订阅前就失败了。")
        return

    s = json.loads(f.read_text(encoding="utf-8"))
    lat = s.get("latency_ms") or {}
    print(f"| 项 | 值 |")
    print(f"|---|---|")
    print(f"| 节点池 | {s.get('pool')} |")
    print(f"| 存活 | **{s.get('alive')}** |")
    if s.get("veterans"):
        print(f"| 老兵名单 | {s['veterans']}（跨轮沉淀，下轮 A 段直接复测） |")
    print(f"| 协议分布 | {s.get('by_proto')} |")
    print(f"| 延迟范围 | {lat.get('min')} ~ {lat.get('max')} ms |")
    print(f"| 更新时间 | {s.get('updated_at')} |")
    print(f"| 已提交 | {os.environ.get('COMMITTED', 'n/a')} |")
    print(f"\n存活判定：经节点实际请求 `{s.get('test_url')}` 返回 204。")

    if not s.get("alive"):
        print("\n> 本次存活为 0，已跳过提交以保留上一次的可用订阅。")

    ss = OUT / "source_stats.json"
    if ss.exists():
        rows = json.loads(ss.read_text(encoding="utf-8")).get("sources", [])
        hit = [r for r in rows if r["alive"]]
        print(f"\n### 源存活率排行（{len(hit)}/{len(rows)} 个源有产出）\n")
        print("| 源 | 节点数 | 存活 | 存活率 | 均延迟 |")
        print("|---|---:|---:|---:|---:|")
        for r in rows[:12]:
            ms = f"{r['avg_latency_ms']}ms" if r["avg_latency_ms"] else "—"
            print(f"| `{r['source']}` | {r['nodes']} | {r['alive']} | "
                  f"{r['alive_rate']:.3f}% | {ms} |")
        if len(rows) > 12:
            zero = sum(1 for r in rows[12:] if not r["alive"])
            print(f"\n其余 {len(rows) - 12} 个源中 {zero} 个本轮无存活。"
                  f"完整数据见 `output/source_stats.json`。")


if __name__ == "__main__":
    main()
