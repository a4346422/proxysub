"""Clash YAML 订阅解析 → 统一节点 dict（与 collect.py 的结构一致）。

公开的 Clash 订阅常有不合规 YAML（未加引号的特殊字符、重复 key），
safe_load 失败时退回逐条 flow-mapping 解析，尽量抢救。
"""
import re

import yaml


def _load(text):
    """返回 proxies 列表。整体解析失败时逐行抢救 flow mapping 条目。"""
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            return [p for p in data["proxies"] if isinstance(p, dict)]
    except yaml.YAMLError:
        pass

    out = []
    for line in text.splitlines():
        s = line.strip()
        if not (s.startswith("- {") and s.endswith("}")):
            continue
        try:
            p = yaml.safe_load(s[2:])
            if isinstance(p, dict):
                out.append(p)
        except yaml.YAMLError:
            continue
    return out


def _net_of(p):
    """Clash network 字段 → xray network"""
    net = (p.get("network") or "tcp").lower()
    return {"http": "h2", "gun": "grpc"}.get(net, net)


def _ws_opts(p):
    """ws-opts / ws-path / ws-headers 多种历史写法都要兼容"""
    path, host = "", ""
    o = p.get("ws-opts")
    if isinstance(o, dict):
        path = o.get("path") or ""
        h = o.get("headers")
        if isinstance(h, dict):
            host = h.get("Host") or h.get("host") or ""
    if not path:
        path = p.get("ws-path") or ""
    if not host:
        h = p.get("ws-headers")
        if isinstance(h, dict):
            host = h.get("Host") or h.get("host") or ""
        elif isinstance(h, str):
            m = re.search(r"Host\s*[:=]\s*([^,;\s]+)", h, re.I)
            host = m.group(1) if m else ""
    return str(path), str(host)


def convert(p):
    """单个 Clash proxy → 节点 dict；不支持返回 None"""
    t = (p.get("type") or "").lower()
    server, port = p.get("server"), p.get("port")
    if not server or port is None:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None

    name = str(p.get("name") or "")
    tls_on = bool(p.get("tls")) or t == "trojan"  # trojan 恒 TLS
    sni = p.get("sni") or p.get("servername") or ""
    net = _net_of(p)
    path, host = _ws_opts(p)

    if net == "grpc":
        g = p.get("grpc-opts")
        svc = g.get("grpc-service-name", "") if isinstance(g, dict) else ""
    else:
        svc = ""

    base = {
        "addr": str(server), "port": port, "name": name,
        "net": net, "tls": "tls" if tls_on else "",
        "host": str(host), "path": str(path),
        "sni": str(sni), "serviceName": str(svc),
        "alpn": "", "fp": str(p.get("client-fingerprint") or ""),
        "src": "clash",
    }

    if t == "vmess":
        if not p.get("uuid"):
            return None
        base.update(proto="vmess", id=str(p["uuid"]),
                    aid=int(p.get("alterId") or 0),
                    scy=str(p.get("cipher") or "auto"),
                    type=str(p.get("header-type") or "none"))
    elif t == "vless":
        if not p.get("uuid"):
            return None
        ro = p.get("reality-opts")
        if isinstance(ro, dict):
            base["tls"] = "reality"
            base["pbk"] = str(ro.get("public-key") or "")
            base["sid"] = str(ro.get("short-id") or "")
        base.update(proto="vless", id=str(p["uuid"]),
                    flow=str(p.get("flow") or ""))
    elif t == "trojan":
        if not p.get("password"):
            return None
        base.update(proto="trojan", id=str(p["password"]))
    elif t == "ss":
        if not (p.get("cipher") and p.get("password") is not None):
            return None
        base.update(proto="ss", method=str(p["cipher"]),
                    password=str(p["password"]), tls="")
    else:
        return None  # ssr / hysteria / tuic 等本流程不支持

    return base


def parse_clash(text):
    """Clash YAML 文本 → [节点 dict]"""
    return [n for n in (convert(p) for p in _load(text)) if n]
