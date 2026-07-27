"""查存活节点的真实出口 IP、国家、ISP，回写 alive.json。

为什么需要：节点名里的国家标注**大量不实**。实测中「荷兰」节点出口在
美国、「俄罗斯联邦」在德国、「香港」在土耳其。名字是上游随手写的，
只有实际请求 IP 查询服务才知道真实落地。

拿到 country_code 后，formats.py 的节点名会带上真实国家码而非猜测值。
"""
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import xray_batch as xb
from countries import cc_to_name

ROOT = Path(__file__).parent
TEMP = ROOT / "temp"
BASE_PORT = int(os.environ.get("IP_BASE_PORT", 27001))
# 出口查询走的是节点自身带宽，高并发会互相拖垮 —— 实测并发 6 时
# 7/19 查不到，降到 3 后 15/19 成功
WORKERS = int(os.environ.get("IP_WORKERS", 3))
TIMEOUT = int(os.environ.get("IP_TIMEOUT", 20))
ROUNDS = int(os.environ.get("IP_ROUNDS", 2))

# (url, ip字段, 国家字段, ISP字段) —— 单源易失败，多源轮询
# (url, ip字段, 国家码字段, 国家名字段, ISP字段)
# ipinfo 只返回国家码，国家名靠 CC_NAME 兜底
APIS = [
    ("http://ip-api.com/json/?fields=query,countryCode,country,isp",
     "query", "countryCode", "country", "isp"),
    ("https://ipinfo.io/json", "ip", "country", None, "org"),
    ("https://api.ipify.org?format=json", "ip", None, None, None),
]

def query(port):
    """经指定 socks 端口查出口信息；全部失败返回 None"""
    for _ in range(ROUNDS):
        for url, ik, ck, nk, ok in APIS:
            try:
                r = subprocess.run(
                    ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{port}",
                     "--max-time", str(TIMEOUT), url],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=TIMEOUT + 5)
                d = json.loads(r.stdout)
                if d.get(ik):
                    cc = (d.get(ck) or "").upper()[:2]
                    return {"exit_ip": d[ik], "country_code": cc,
                            "country": cc_to_name(cc, d.get(nk) or ""),
                            "isp": (d.get(ok) or "")[:40]}
            except Exception:
                pass
            time.sleep(0.15)
    return None


def main():
    f = TEMP / "alive.json"
    if not f.exists():
        print("缺 temp/alive.json，先跑 check_alive.py")
        return 1
    nodes = json.loads(f.read_text(encoding="utf-8"))
    if not nodes:
        print("alive.json 为空，跳过")
        return 0

    cfg, mapping = xb.build_config(nodes, base_port=BASE_PORT)
    if not mapping:
        print("无可构造节点")
        return 0

    print(f"查 {len(mapping)} 个存活节点的出口 IP（并发 {WORKERS}）")
    proc, _ = xb.start_xray(cfg, "ipchk")
    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            results = list(ex.map(lambda pn: query(pn[0]), mapping))
    finally:
        xb.stop_xray(proc)

    by_key = {}
    for (port, n), info in zip(mapping, results):
        if info:
            by_key[n.get("key")] = info

    for n in nodes:
        info = by_key.get(n.get("key"))
        if info:
            n.update(info)
    f.write_text(json.dumps(nodes, ensure_ascii=False), encoding="utf-8")

    got = len(by_key)
    print(f"查到 {got}/{len(mapping)}\n")
    print(f"{'节点地址':<26} {'出口IP':<16} {'国家':<5} {'ISP':<26}")
    print("-" * 78)
    for n in nodes:
        cc = n.get("country_code") or "?"
        print(f"{str(n['addr'])[:25]:<26} {n.get('exit_ip', '-'):<16} "
              f"{cc:<5} {(n.get('isp') or '')[:26]:<26}")

    # 出口 IP 相同 = 同一落地机，客户端里换着用没有意义
    shared = {}
    for n in nodes:
        ip = n.get("exit_ip")
        if ip:
            shared.setdefault(ip, []).append(n["addr"])
    dup = {ip: a for ip, a in shared.items() if len(a) > 1}
    if dup:
        print(f"\n共用同一出口 IP 的节点（同一落地机，切换无意义）:")
        for ip, addrs in dup.items():
            print(f"  {ip} ← {len(addrs)} 个: {', '.join(str(a)[:22] for a in addrs)}")

    print(f"\n-> 已回写 {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
