"""节点 dict → 分享链接。

Clash 源解析出来的节点没有原始链接，导出 v2rayN 订阅时需要反向生成。
链接式源保留了原始 link，优先原样输出以免丢失字段。
"""
import base64
import json
import urllib.parse


def _b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")


def _q(n, extra=None):
    """构造 vless/trojan 的 query 部分"""
    q = {}
    net = n.get("net") or "tcp"
    q["type"] = net
    sec = n.get("tls") or ""
    if sec:
        q["security"] = sec
    for src, dst in (("host", "host"), ("path", "path"), ("sni", "sni"),
                     ("alpn", "alpn"), ("fp", "fp"), ("flow", "flow"),
                     ("pbk", "pbk"), ("sid", "sid")):
        v = n.get(src)
        if v:
            q[dst] = str(v)
    if net == "grpc" and n.get("serviceName"):
        q["serviceName"] = str(n["serviceName"])
    if extra:
        q.update(extra)
    return urllib.parse.urlencode(q, safe="/+=")


def to_link(n, name=None):
    """节点 dict → 链接字符串。name 非空则覆盖节点名。"""
    nm = name if name is not None else (n.get("name") or "")
    p = n.get("proto")

    # 链接式源：仅需改名时，直接改原链接的 fragment，保留全部原始字段
    if n.get("link") and n.get("src") != "clash":
        link = n["link"]
        if p == "vmess":
            try:
                raw = link[8:]
                raw += "=" * (-len(raw) % 4)
                c = json.loads(base64.b64decode(raw).decode("utf-8", "ignore"))
                c["ps"] = nm
                return "vmess://" + _b64(json.dumps(c, ensure_ascii=False,
                                                    separators=(",", ":")))
            except Exception:
                return link
        base = link.split("#", 1)[0]
        return f"{base}#{urllib.parse.quote(nm)}"

    if p == "vmess":
        c = {
            "v": "2", "ps": nm, "add": n["addr"], "port": str(n["port"]),
            "id": n["id"], "aid": str(n.get("aid", 0)),
            "scy": n.get("scy") or "auto", "net": n.get("net") or "tcp",
            "type": n.get("type") or "none", "host": n.get("host") or "",
            "path": n.get("path") or "", "tls": n.get("tls") or "",
            "sni": n.get("sni") or "", "alpn": n.get("alpn") or "",
            "fp": n.get("fp") or "",
        }
        return "vmess://" + _b64(json.dumps(c, ensure_ascii=False,
                                            separators=(",", ":")))
    if p == "vless":
        # 与 formats 一致：Reality 缺 pbk 无法构造可用链接
        if str(n.get("tls") or "").lower() == "reality" and not str(n.get("pbk") or "").strip():
            return None
        return (f"vless://{n['id']}@{n['addr']}:{n['port']}?"
                f"{_q(n, {'encryption': 'none'})}#{urllib.parse.quote(nm)}")
    if p == "trojan":
        return (f"trojan://{urllib.parse.quote(str(n['id']), safe='')}"
                f"@{n['addr']}:{n['port']}?{_q(n)}#{urllib.parse.quote(nm)}")
    if p == "ss":
        userinfo = _b64(f"{n['method']}:{n['password']}")
        return (f"ss://{userinfo}@{n['addr']}:{n['port']}"
                f"#{urllib.parse.quote(nm)}")
    return None
