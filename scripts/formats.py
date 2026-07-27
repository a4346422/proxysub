"""把存活节点输出成 4 种订阅格式 + 状态文件。

取代原 build_sub.py：去掉 IP 纯净度（trust）相关字段与主备清单分级。
Clash / sing-box 的字段映射与 clash_parse.py:convert() 互为逆向。
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


def build_names(nodes):
    """生成节点名，同国家按延迟顺序编号：US 美国1 / US 美国2 …

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


def to_clash(n, name):
    """节点 dict → Clash proxy dict；不支持返回 None"""
    p = n["proto"]
    net = str(n.get("net") or "tcp")
    if net == "gun":
        net = "grpc"
    # Clash 不支持 h2/http 传输的这些免费节点组合，且 xray 26 已移除
    if net in ("h2", "http"):
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
    """节点 dict → sing-box outbound dict；不支持返回 None"""
    p = n["proto"]
    net = str(n.get("net") or "tcp")
    if net in ("h2", "http"):
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
    nodes.sort(key=lambda n: n.get("latency_ms", 999999))
    OUT.mkdir(parents=True, exist_ok=True)

    # 同国家按延迟顺序编号（US 美国1 / US 美国2 …），
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
                     for p in sorted({n["proto"] for n in nodes})},
        "latency_ms": {
            "min": nodes[0]["latency_ms"] if nodes else None,
            "max": nodes[-1]["latency_ms"] if nodes else None,
        },
        "test_url": os.environ.get("TEST_URL",
                                   "https://www.google.com/generate_204"),
        # 老兵名单规模：跨轮沉淀的稳定节点数，反映增量调度的积累效果
        "veterans": len(json.loads((OUT / "veterans.json").read_text(
            encoding="utf-8")).get("nodes", []))
        if (OUT / "veterans.json").exists() else 0,
        "note": "alive = 经节点实际请求 test_url 返回 204 的节点数",
    }
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
