"""把存活节点输出成 4 种订阅格式 + 状态文件。

取代原 build_sub.py：去掉 IP 纯净度（trust）相关字段与主备清单分级。
Clash / sing-box 的字段映射与 clash_parse.py:convert() 互为逆向。

Reality 导出补全 reality-opts / utls；缺 pbk 的 Reality 整节点丢弃。
不做延迟/条数等质量门禁，测活通过即尽量全量输出。
"""
import base64
import json
import os
import time
from pathlib import Path

import yaml

from countries import CC_NAME
from to_link import to_link

ROOT = Path(__file__).parent
TEMP = ROOT / "temp"
OUT = Path(os.environ.get("OUTPUT_DIR") or (ROOT.parent / "output"))
COUNTRY_PRIORITY = {"HK": 0, "JP": 1, "SG": 2, "US": 3}


def country_label(n):
    """节点的国家标签，如「US 美国」。查不到出口则为「UNKNOWN」。

    只用 check_ip.py 实测到的出口国家 —— 上游节点名里的国家标注大量不实
    （实测「荷兰」出口在美国、「香港」在土耳其），原名一并丢弃。
    """
    cc = (n.get("country_code") or "").upper()
    if not cc:
        return "UNKNOWN"
    name = n.get("country") or CC_NAME.get(cc) or cc
    return f"{cc} {name}" if name != cc else cc


def output_sort_key(n):
    """按国家分组输出：HK/JP/SG/US 优先，同国家内按上游节点名排序。"""
    cc = (n.get("country_code") or "").upper()
    if not cc or cc in ("?", "UNKNOWN"):
        country_key = (2, "ZZ")
    elif cc in COUNTRY_PRIORITY:
        country_key = (0, COUNTRY_PRIORITY[cc])
    else:
        country_key = (1, cc)
    name = str(n.get("name") or "").casefold()
    return (*country_key, name, n.get("latency_ms", 999999))


def build_names(nodes):
    """生成节点名，同国家按当前输出顺序编号：US 美国1 / US 美国2 …

    单个国家只有一个节点时也带 1，保证命名规则一致、便于客户端排序。
    """
    seq, names = {}, []
    for n in nodes:
        lb = country_label(n)
        seq[lb] = seq.get(lb, 0) + 1
        names.append(f"{lb}{seq[lb]}")
    return names


def _tls_on(n):
    return str(n.get("tls") or "").lower() in ("tls", "reality", "xtls", "true")


def _is_reality(n):
    return str(n.get("tls") or "").lower() == "reality"


def _reality_exportable(n):
    """Reality 无 public key 时无法在 Clash/sing-box/链接里完整表达，整节点丢弃。"""
    if not _is_reality(n):
        return True
    return bool(str(n.get("pbk") or "").strip())


def _fingerprint(n):
    return str(n.get("fp") or "").strip() or "chrome"


def to_clash(n, name):
    """节点 dict → Clash / Mihomo proxy dict；不支持返回 None。

    Reality 必须带 reality-opts.public-key / short-id，以及 client-fingerprint，
    否则 meta 内核无法握手（Xray 测活能过、Clash 订阅却全挂）。
    """
    p = n["proto"]
    net = str(n.get("net") or "tcp")
    if net == "gun":
        net = "grpc"
    # Clash 不支持 h2/http 传输的这些免费节点组合，且 xray 26 已移除
    if net in ("h2", "http"):
        return None
    # Reality 缺 pbk 会退化成假 TLS，直接丢弃
    if not _reality_exportable(n):
        return None

    c = {"name": name, "server": n["addr"], "port": int(n["port"])}
    if p == "vmess":
        c.update(type="vmess", uuid=n["id"], alterId=int(n.get("aid") or 0),
                 cipher=str(n.get("scy") or "auto"))
    elif p == "vless":
        c.update(type="vless", uuid=n["id"])
        if n.get("flow"):
            c["flow"] = n["flow"]
    elif p == "trojan":
        c.update(type="trojan", password=str(n["id"]))
    elif p == "ss":
        c.update(type="ss", cipher=n["method"], password=str(n["password"]))
        return c  # ss 无 tls/network 字段
    else:
        return None

    if _tls_on(n):
        c["tls"] = True
        c["skip-cert-verify"] = True
        sni = n.get("sni") or n.get("host")
        if sni:
            c["servername"] = str(sni).split(",")[0]
        if _is_reality(n):
            # Mihomo / Clash Meta 字段名
            c["client-fingerprint"] = _fingerprint(n)
            ro = {}
            if n.get("pbk"):
                ro["public-key"] = str(n["pbk"])
            # short-id 允许空字符串（部分服务端如此配置）
            if n.get("sid") is not None and str(n.get("sid")) != "":
                ro["short-id"] = str(n["sid"])
            elif n.get("sid") == "":
                ro["short-id"] = ""
            if n.get("pbk"):
                c["reality-opts"] = ro
        elif n.get("fp"):
            c["client-fingerprint"] = _fingerprint(n)
        alpn = str(n.get("alpn") or "").strip()
        if alpn:
            c["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]

    if net != "tcp":
        c["network"] = net
    if net == "ws":
        ws = {"path": str(n.get("path") or "/")}
        if n.get("host"):
            ws["headers"] = {"Host": str(n["host"])}
        c["ws-opts"] = ws
    elif net == "grpc":
        c["grpc-opts"] = {"grpc-service-name":
                          str(n.get("serviceName") or n.get("path") or "")}
    return c


def to_singbox(n, name):
    """节点 dict → sing-box outbound dict；不支持返回 None。

    Reality 走 tls.reality + utls，与官方字段对齐。
    """
    p = n["proto"]
    net = str(n.get("net") or "tcp")
    if net in ("h2", "http"):
        return None
    if not _reality_exportable(n):
        return None

    o = {"tag": name, "server": n["addr"], "server_port": int(n["port"])}
    if p == "vmess":
        o.update(type="vmess", uuid=n["id"], alter_id=int(n.get("aid") or 0),
                 security=str(n.get("scy") or "auto"))
    elif p == "vless":
        o.update(type="vless", uuid=n["id"])
        if n.get("flow"):
            o["flow"] = n["flow"]
    elif p == "trojan":
        o.update(type="trojan", password=str(n["id"]))
    elif p == "ss":
        o.update(type="shadowsocks", method=n["method"],
                 password=str(n["password"]))
        return o
    else:
        return None

    if _tls_on(n):
        tls = {"enabled": True, "insecure": True}
        sni = n.get("sni") or n.get("host")
        if sni:
            tls["server_name"] = str(sni).split(",")[0]
        alpn = str(n.get("alpn") or "").strip()
        if alpn:
            tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        if _is_reality(n):
            tls["insecure"] = False  # reality 不依赖系统 CA
            tls["utls"] = {"enabled": True, "fingerprint": _fingerprint(n)}
            reality = {"enabled": True}
            if n.get("pbk"):
                reality["public_key"] = str(n["pbk"])
            if n.get("sid") is not None:
                reality["short_id"] = str(n.get("sid") or "")
            tls["reality"] = reality
        elif n.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": _fingerprint(n)}
        o["tls"] = tls
    if net == "ws":
        t = {"type": "ws", "path": str(n.get("path") or "/")}
        if n.get("host"):
            t["headers"] = {"Host": str(n["host"])}
        o["transport"] = t
    elif net in ("grpc", "gun"):
        o["transport"] = {"type": "grpc", "service_name":
                          str(n.get("serviceName") or n.get("path") or "")}
    return o


def build_clash_yaml(nodes, names):
    proxies = []
    for n, nm in zip(nodes, names):
        c = to_clash(n, nm)
        if c:
            proxies.append(c)
    pnames = [p["name"] for p in proxies]
    doc = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select",
             "proxies": ["AUTO"] + pnames},
            {"name": "AUTO", "type": "url-test", "proxies": pnames or ["DIRECT"],
             "url": "https://www.google.com/generate_204", "interval": 300},
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,PROXY"],
    }
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


def build_singbox_json(nodes, names):
    outs = []
    for n, nm in zip(nodes, names):
        o = to_singbox(n, nm)
        if o:
            outs.append(o)
    tags = [o["tag"] for o in outs]
    doc = {
        "log": {"level": "info"},
        "inbounds": [{"type": "mixed", "tag": "mixed-in",
                      "listen": "127.0.0.1", "listen_port": 7890}],
        "outbounds": [
            {"type": "selector", "tag": "PROXY",
             "outbounds": ["AUTO"] + tags, "default": "AUTO"},
            {"type": "urltest", "tag": "AUTO", "outbounds": tags or ["direct"],
             "url": "https://www.google.com/generate_204", "interval": "5m"},
            *outs,
            {"type": "direct", "tag": "direct"},
        ],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


def main():
    src = TEMP / "alive.json"
    if not src.exists():
        print("缺 temp/alive.json，先跑 check_alive.py")
        return 1
    nodes = json.loads(src.read_text(encoding="utf-8"))
    # 缺 pbk 的 Reality 无法完整导出，从全量订阅中剔除（不做延迟/条数门禁）
    dropped_reality = [n for n in nodes if not _reality_exportable(n)]
    if dropped_reality:
        nodes = [n for n in nodes if _reality_exportable(n)]
        print(f"  丢弃缺 pbk 的 Reality {len(dropped_reality)} 个（无法完整导出）")
    nodes.sort(key=output_sort_key)
    OUT.mkdir(parents=True, exist_ok=True)

    # 同国家分组后编号（HK/JP/SG/US 优先，同国家内按上游节点名排序），
    # 编号本身即保证了 Clash/sing-box 要求的名称唯一
    names = build_names(nodes)

    links = []
    for n, nm in zip(nodes, names):
        link = to_link(n, name=nm)
        if link:
            links.append(link)

    plain = "\n".join(links) + ("\n" if links else "")
    (OUT / "nodes.txt").write_text(plain, encoding="utf-8")
    (OUT / "sub.txt").write_text(
        base64.b64encode(plain.encode("utf-8")).decode("ascii"),
        encoding="utf-8")
    (OUT / "clash.yaml").write_text(build_clash_yaml(nodes, names),
                                    encoding="utf-8")
    (OUT / "singbox.json").write_text(build_singbox_json(nodes, names),
                                      encoding="utf-8")

    pool = TEMP / "nodes_all.json"
    pool_n = len(json.loads(pool.read_text(encoding="utf-8"))) if pool.exists() else 0
    latencies = [n["latency_ms"] for n in nodes if "latency_ms" in n]
    status = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "updated_ts": int(time.time()),
        "pool": pool_n,
        "alive": len(nodes),
        "links": len(links),
        "by_country": {cc: sum(1 for n in nodes
                               if (n.get("country_code") or "?") == cc)
                       for cc in sorted({n.get("country_code") or "?"
                                         for n in nodes})},
        "exit_ips": len({n["exit_ip"] for n in nodes if n.get("exit_ip")}),
        "by_proto": {p: sum(1 for n in nodes if n["proto"] == p)
                     for p in sorted({n["proto"] for n in nodes})} if nodes else {},
        "latency_ms": {
            "min": min(latencies) if latencies else None,
            "max": max(latencies) if latencies else None,
        },
        # 老兵名单规模：跨轮沉淀的稳定节点数，反映增量调度的积累效果
        "veterans": len(json.loads((OUT / "veterans.json").read_text(
            encoding="utf-8")).get("nodes", []))
        if (OUT / "veterans.json").exists() else 0,
        "drop_reality_no_pbk": len(dropped_reality),
        "note": "alive = 经节点实际请求 test_urls 任一返回 204 且可完整导出的节点数",
    }
    raw_urls = (os.environ.get("TEST_URLS") or "").strip()
    if raw_urls:
        test_urls = [u.strip() for u in raw_urls.split(",") if u.strip()]
    else:
        single = (os.environ.get("TEST_URL") or "").strip()
        test_urls = [single] if single else [
            "https://www.google.com/generate_204",
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
        ]
    status["test_urls"] = test_urls
    status["test_url"] = test_urls[0] if test_urls else ""
    (OUT / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"节点池 {pool_n} → 存活 {len(nodes)} → 输出 {len(links)} 条链接")
    print(f"  nodes.txt / sub.txt / clash.yaml / singbox.json / status.json")
    print(f"  -> {OUT}")
    for n, nm in list(zip(nodes, names))[:10]:
        print(f"  {nm[:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
