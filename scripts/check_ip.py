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

import veterans as vt
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
# 缓存出口信息的有效期。落地出口会变（换机房/换上游），过期就重查。
# 24 小时 = cron 每 2 小时一轮，同一节点约每 12 轮重查一次。
GEO_TTL_SEC = int(os.environ.get("GEO_TTL_SEC", 86400))

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
                            "isp": (d.get(ok) or "")[:40],
                            # 供下轮判断缓存是否过期
                            "geo_ts": int(time.time())}
            except Exception:
                pass
            time.sleep(0.15)
    return None


def _writeback(nodes, f):
    """回写 alive.json，并把出口信息同步进老兵名单。

    名单同步是关键一步：check_alive.py 写名单时还没有出口信息（本步骤在它
    之后才跑），不同步的话新晋老兵永远存不进国家，下轮 check_ip 失败时
    整份订阅节点名会退化成 UNKNOWN。
    """
    f.write_text(json.dumps(nodes, ensure_ascii=False), encoding="utf-8")
    try:
        hit = vt.refresh_geo(nodes)
        if hit:
            print(f"已把出口信息同步进老兵名单 {hit} 个")
    except Exception as e:
        # 名单同步失败不该让整步失败（本步骤是 continue-on-error，
        # 但 alive.json 已经写好了，没必要因为缓存写不进去而丢掉）
        print(f"老兵名单同步失败（{str(e)[:60]}），跳过")


def main():
    f = TEMP / "alive.json"
    if not f.exists():
        print("缺 temp/alive.json，先跑 check_alive.py")
        return 1
    nodes = json.loads(f.read_text(encoding="utf-8"))
    if not nodes:
        print("alive.json 为空，跳过")
        return 0

    # 只查没有缓存出口的节点。老兵名单里已带 exit_ip 的（同一台机器落地
    # 国家基本不变）直接复用 —— 查询走节点自身带宽且 WORKERS=3，465 个
    # 节点要 155 波串行、约 4 分钟，占全流程 30%。跳过缓存后每轮只查新
    # 发现的几十个。REFRESH_GEO=1 可强制全量重查。
    #
    # 缓存不能永久有效：机器的落地出口确实会变（换机房、换上游），
    # 缓存超过 GEO_TTL_SEC（默认 24 小时）就重查，避免国家标注长期失准。
    force = os.environ.get("REFRESH_GEO", "0") == "1"
    now = int(time.time())

    def stale(n):
        if not n.get("exit_ip"):
            return True
        ts = n.get("geo_ts")
        if not isinstance(ts, int):
            return True  # 老数据没有时间戳，重查一次补上
        return now - ts > GEO_TTL_SEC

    todo = nodes if force else [n for n in nodes if stale(n)]
    cached = len(nodes) - len(todo)

    cfg, mapping = xb.build_config(todo, base_port=BASE_PORT)
    if not mapping:
        print(f"无需查询（{cached} 个全部命中缓存）" if cached else "无可构造节点")
        _writeback(nodes, f)
        return 0

    print(f"查 {len(mapping)} 个存活节点的出口 IP（并发 {WORKERS}）"
          f"{f'，{cached} 个复用缓存' if cached else ''}")
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
    _writeback(nodes, f)

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
