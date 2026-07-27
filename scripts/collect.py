"""采集公开订阅源，解析节点链接，去重后输出 temp/nodes_all.json

订阅源可用 sources.txt 外置覆盖（改源不必改代码）：
一行一个 URL，`#` 开头为注释；YAML 类源在 URL 后加 ` clash` 标记。
"""
import base64
import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from clash_parse import parse_clash

ROOT = Path(__file__).parent
TEMP = ROOT / "temp"
SOURCES_FILE = Path(os.environ.get("SOURCES_FILE")
                    or (ROOT.parent / "sources.txt"))

# 以下为内置默认源，sources.txt 存在时被其完全取代
# 链接式订阅（base64 或明文，一行一个 xxx:// 链接）
SOURCES = [
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
]

# Clash YAML 订阅（proxies: 列表）
CLASH_SOURCES = [
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
]

SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")


def load_sources():
    """读 sources.txt；不存在则用内置默认。返回 (链接式, clash式)"""
    if not SOURCES_FILE.exists():
        return list(SOURCES), list(CLASH_SOURCES)

    plain, clash = [], []
    for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        url = parts[0]
        tags = {p.lower() for p in parts[1:]}
        targets = expand_dates(url) if "{" in url else [url]
        (clash if "clash" in tags else plain).extend(targets)

    print(f"订阅源来自 {SOURCES_FILE.name}: "
          f"{len(plain)} 链接式 + {len(clash)} clash式\n")
    return plain, clash


def expand_dates(url, days=None):
    """展开 URL 里的日期占位符，返回最近 N 天的候选。

    有些源按日期滚动命名（如 free-nodes 的 v202607262），硬编码文件名
    第二天就 404。占位符：{Y} 年 {m} 月 {d} 日 {YMD}=%Y%m%d。
    过期日期返回 404 会被自动跳过，所以多试几天无副作用。
    """
    if days is None:
        # 默认只取当天：实测回溯日的文件各只补 ~19 个节点，且连续两轮零存活
        days = int(os.environ.get("DATE_LOOKBACK_DAYS", 1))
    out = []
    now = datetime.now(timezone.utc)
    for i in range(days):
        d = now - timedelta(days=i)
        out.append(url.replace("{YMD}", d.strftime("%Y%m%d"))
                      .replace("{Y}", d.strftime("%Y"))
                      .replace("{m}", d.strftime("%m"))
                      .replace("{d}", d.strftime("%d")))
    return out


def b64pad(s):
    """补齐 base64 padding 并统一 urlsafe 字符"""
    s = s.strip().replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def try_b64decode(text):
    """订阅体可能是 base64，也可能已是明文；解不出就原样返回"""
    compact = re.sub(r"\s", "", text)
    if not compact or any(sch in text for sch in SCHEMES):
        return text
    try:
        return base64.b64decode(b64pad(compact)).decode("utf-8", "ignore")
    except Exception:
        return text


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def parse_vmess(link):
    """vmess://<base64 of json>"""
    try:
        raw = base64.b64decode(b64pad(link[8:])).decode("utf-8", "ignore")
        c = json.loads(raw)
    except Exception:
        return None
    addr, port = c.get("add"), c.get("port")
    uid = c.get("id")
    if not (addr and port and uid):
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    return {
        "proto": "vmess", "link": link, "name": c.get("ps") or "",
        "addr": addr, "port": port, "id": uid,
        "aid": int(c.get("aid") or 0), "scy": c.get("scy") or "auto",
        "net": c.get("net") or "tcp", "type": c.get("type") or "none",
        "host": c.get("host") or "", "path": c.get("path") or "",
        "tls": c.get("tls") or "", "sni": c.get("sni") or "",
        "alpn": c.get("alpn") or "", "fp": c.get("fp") or "",
    }


def _common_url_node(link, proto):
    """vless / trojan 共用 userinfo@host:port?query#name 结构"""
    try:
        u = urllib.parse.urlparse(link)
    except Exception:
        return None
    if not (u.hostname and u.port and u.username):
        return None
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    return {
        "proto": proto, "link": link,
        "name": urllib.parse.unquote(u.fragment or ""),
        "addr": u.hostname, "port": u.port,
        "id": urllib.parse.unquote(u.username),
        "net": q.get("type", "tcp"), "tls": q.get("security", ""),
        "host": q.get("host", ""), "path": q.get("path", ""),
        "sni": q.get("sni", ""), "alpn": q.get("alpn", ""),
        "fp": q.get("fp", ""), "flow": q.get("flow", ""),
        "pbk": q.get("pbk", ""), "sid": q.get("sid", ""),
        "headerType": q.get("headerType", "none"),
        "serviceName": q.get("serviceName", ""),
    }


def parse_ss(link):
    """ss://  两种形态：base64(method:pass)@host:port  或  base64(全部)"""
    body = link[5:]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = urllib.parse.unquote(frag)
    body = body.split("?", 1)[0]

    if "@" in body:
        userinfo, hostpart = body.rsplit("@", 1)
        try:
            userinfo = base64.b64decode(b64pad(userinfo)).decode("utf-8", "ignore")
        except Exception:
            userinfo = urllib.parse.unquote(userinfo)
    else:
        try:
            decoded = base64.b64decode(b64pad(body)).decode("utf-8", "ignore")
        except Exception:
            return None
        if "@" not in decoded:
            return None
        userinfo, hostpart = decoded.rsplit("@", 1)

    if ":" not in userinfo or ":" not in hostpart:
        return None
    method, password = userinfo.split(":", 1)
    host, port = hostpart.rsplit(":", 1)
    try:
        port = int(port)
    except ValueError:
        return None
    host = host.strip("[]")
    if not host:
        return None
    return {"proto": "ss", "link": link, "name": name, "addr": host,
            "port": port, "method": method, "password": password}


def parse(link):
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("vless://"):
        return _common_url_node(link, "vless")
    if link.startswith("trojan://"):
        return _common_url_node(link, "trojan")
    if link.startswith("ss://"):
        return parse_ss(link)
    return None


def fingerprint(n):
    """同一服务端+凭证视为重复，忽略节点名差异"""
    cred = n.get("id") or n.get("password") or ""
    return f"{n['proto']}|{n['addr']}|{n['port']}|{cred}"


def endpoint(n):
    """端点指纹：同协议+同地址+同端口。

    公开池里大量节点是同一入口配几百个不同 UUID（实测单个端点被复用
    602 次），测活结果必然相同，测一次就够。这层去重把 4.1 万压到 3 万。
    """
    return f"{n['proto']}|{str(n['addr']).lower()}|{n['port']}"


def src_label(url):
    """URL → 简短来源标签，如 Leon406/SubCrawler:vless"""
    parts = url.rstrip("/").split("/")
    try:
        owner, repo = parts[3], parts[4]
    except IndexError:
        return url[:40]
    return f"{owner}/{repo}:{parts[-1][:22]}"


def _add(n, seen, nodes, endpoints=None, src=None):
    """去重后加入。返回是否新增。

    两层：凭证级（同端点不同 UUID 视为不同）→ 端点级（同端点只留一个）。
    src 记录首个收录该节点的源，用于后续按源统计存活率。
    """
    fp = fingerprint(n)
    if fp in seen:
        return False
    if endpoints is not None:
        ep = endpoint(n)
        if ep in endpoints:
            return False
        endpoints.add(ep)
    seen.add(fp)
    n["key"] = fp  # 注意：不能用 "fp"，那是 TLS utls fingerprint 字段
    if src:
        n["src_url"] = src
    nodes.append(n)
    return True


def main():
    TEMP.mkdir(exist_ok=True)
    seen, nodes = set(), []
    # DEDUP_ENDPOINT=0 可关闭端点级去重（保留同端点的全部 UUID）
    endpoints = set() if os.environ.get("DEDUP_ENDPOINT", "1") != "0" else None
    stats = []
    plain_sources, clash_sources = load_sources()

    for url in plain_sources:
        try:
            text = try_b64decode(fetch(url))
        except Exception as e:
            stats.append((url, f"FAIL {str(e)[:20]}", 0, 0))
            continue

        found = new = 0
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith(SCHEMES):
                continue
            found += 1
            n = parse(line)
            if n and _add(n, seen, nodes, endpoints, src_label(url)):
                new += 1
        stats.append((url, "OK", found, new))

    for url in clash_sources:
        try:
            proxies = parse_clash(fetch(url))
        except Exception as e:
            stats.append((url, f"FAIL {str(e)[:20]}", 0, 0))
            continue
        new = sum(1 for n in proxies
                  if _add(n, seen, nodes, endpoints, src_label(url)))
        stats.append((url, "CLASH", len(proxies), new))

    for url, st, found, new in stats:
        print(f"[{st:>6}] +{new:<5} / {found:<5} {url.split('/')[4]}/{url.rsplit('/',1)[-1][:18]}")

    for i, n in enumerate(nodes):
        n["idx"] = i

    out = TEMP / "nodes_all.json"
    out.write_text(json.dumps(nodes, ensure_ascii=False), encoding="utf-8")

    by_proto = {}
    for n in nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    mode = "凭证级+端点级" if endpoints is not None else "仅凭证级"
    print(f"\n去重后共 {len(nodes)} 个节点（{mode}）: {by_proto}")
    print(f"-> {out}")


if __name__ == "__main__":
    main()
