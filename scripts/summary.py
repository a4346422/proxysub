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
    q = s.get("quality") or {}
    print(f"| 项 | 值 |")
    print(f"|---|---|")
    print(f"| 节点池 | {s.get('pool')} |")
    if s.get("alive_raw") is not None and s.get("alive_raw") != s.get("alive"):
        print(f"| 测活原始 | {s.get('alive_raw')} |")
        print(f"| 订阅输出 | **{s.get('alive')}**（质量门禁后） |")
    else:
        print(f"| 存活 | **{s.get('alive')}** |")
    if q:
        _on, _off = '开', '关'
        print(f"| 门禁 | 延迟≤{q.get('latency_max_ms')}ms，"
              f"上限{q.get('max_output_nodes')}，"
              f"出口去重={_on if q.get('dedup_exit_ip') else _off}，"
              f"集群去重={_on if q.get('dedup_cluster', True) else _off} |")
        if q.get('drop_dup_cluster') or q.get('after_dedup_cluster') is not None:
            print(f"| 门禁过程 | 延迟后 {q.get('after_latency')} → "
                  f"出口去重 {q.get('after_dedup_exit', q.get('after_dedup'))} → "
                  f"集群去重 {q.get('after_dedup_cluster', q.get('after_dedup'))} "
                  f"（丢同出口 {q.get('drop_dup_exit', 0)} / "
                  f"同集群 {q.get('drop_dup_cluster', 0)}） |")
    if s.get("veterans"):
        print(f"| 老兵名单 | {s['veterans']}（跨轮沉淀，下轮 A 段直接复测） |")
    print(f"| 协议分布 | {s.get('by_proto')} |")
    print(f"| 延迟范围 | {lat.get('min')} ~ {lat.get('max')} ms |")
    print(f"| 更新时间 | {s.get('updated_at')} |")
    print(f"| 已提交 | {os.environ.get('COMMITTED', 'n/a')} |")
    print(f"\n存活判定：经节点实际请求 `{s.get('test_url')}` 返回 204；"
          f"写入订阅前再经质量门禁（延迟/出口去重/集群去重/结构排序/条数上限）。")

    if not s.get("alive"):
        print("\n> 本次订阅输出为 0，已跳过提交以保留上一次的可用订阅。")

    ss = OUT / "source_stats.json"
    if ss.exists():
        rows = json.loads(ss.read_text(encoding="utf-8")).get("sources", [])
        hit = [r for r in rows if r["alive"]]
        if hit:
            print("\n### 有贡献的源\n")
            print("| 源 | 节点 | 存活 | 存活率 |")
            print("|---|---:|---:|---:|")
            for r in hit[:15]:
                print(f"| `{r['source']}` | {r['nodes']} | {r['alive']} | "
                      f"{r['alive_rate']}% |")


if __name__ == "__main__":
    main()
