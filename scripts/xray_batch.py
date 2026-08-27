"""把节点转成 xray outbound，并生成「N 个 socks inbound ↔ N 个 outbound」的批量配置。

设计要点：不逐个启停内核（4700 次启停不可行），而是一次配置多入站，
每个 socks 端口经 routing 硬绑定到唯一 outbound，从而并发压测。
"""
import json
import os
import socket
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).parent
TEMP = ROOT / "temp"

# 内核路径：CI 里解压到 ./bin/xray；本地可用 XRAY_BIN 指向已有的 xray.exe
XRAY = Path(os.environ.get("XRAY_BIN") or (ROOT.parent / "bin" / "xray"))

BASE_PORT = int(os.environ.get("BASE_PORT", 20001))
# 默认 100 来自全量实测：比 90 更稳，比 150/200 更能保留存活节点。
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", 100))

# Windows 专有，Linux runner 上必须为 0
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# xray 支持的 shadowsocks 加密。老式 CFB/CTR/RC4 已被移除，
# 单个非法 outbound 会导致整份配置加载失败，必须在生成阶段就剔除。
SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none", "plain",
}


def _s(n, key, default=""):
    """订阅源字段类型很脏（tls 可能是 bool、port 可能是 str），统一取字符串"""
    v = n.get(key)
    if v is None or v is False:
        return default
    if v is True:
        return "tls" if key == "tls" else default
    return str(v)


def _stream_settings(n):
    """构造 streamSettings；返回 None 表示该节点用默认 tcp 明文"""
    net = _s(n, "net", "tcp") or "tcp"
    tls = _s(n, "tls").lower()
    ss = {"network": net}

    host, path = _s(n, "host"), _s(n, "path")

    # Xray 26.x 已移除 h2 transport（迁到 XHTTP），保留会让整份配置加载失败
    if net in ("h2", "http"):
        return None

    if net == "ws":
        ws = {"path": path or "/"}
        if host:
            ws["headers"] = {"Host": host}
        ss["wsSettings"] = ws
    elif net in ("grpc", "gun"):
        ss["network"] = "grpc"
        ss["grpcSettings"] = {"serviceName": _s(n, "serviceName") or path}
    elif net == "h2":
        ss["network"] = "h2"
        h2 = {"path": path or "/"}
        if host:
            h2["host"] = [h for h in host.split(",") if h]
        ss["httpSettings"] = h2
    elif net == "tcp":
        if (_s(n, "type") or _s(n, "headerType") or "none") == "http":
            hosts = [h for h in host.split(",") if h]
            ss["tcpSettings"] = {"header": {
                "type": "http",
                "request": {"path": [path or "/"],
                            "headers": {"Host": hosts or [n["addr"]]}},
            }}
    elif net == "kcp":
        ss["kcpSettings"] = {"header": {"type": _s(n, "type") or "none"}}
        if path:
            ss["kcpSettings"]["seed"] = path

    sni = _s(n, "sni") or host
    alpn = [a for a in _s(n, "alpn").replace(",", " ").split() if a]
    utls = _s(n, "fp")

    if tls in ("tls", "xtls"):
        ss["security"] = "tls"
        # 不能写 allowInsecure：xray v26.3.27 起该字段被移除（迁到
        # pinnedPeerCertSha256），写 true 会让整份配置加载失败。
        #
        # 这曾是个静默的大坑：池子里 52% 的节点是 tls/xtls，它们生成的配置
        # 全部非法，drop_bad_outbounds 的 60 次上限根本摘不完，导致整批
        # 100 个节点被跳过 —— 实测 60 批里 41 批如此，B 段只有 16.7% 的
        # 候选真正被测过。老兵名单里 tls:tls 节点数为 0 就是这么来的。
        #
        # 迁移目标 pinnedPeerCertSha256 需要预先知道证书指纹，对公开池
        # 不可行。这里就让证书校验生效（xray 默认行为）：自签/域名不匹配的
        # 节点会握手失败被判死。这比「整批误杀」准确得多。
        t = {}
        if sni:
            t["serverName"] = sni.split(",")[0]
        if alpn:
            t["alpn"] = alpn
        if utls:
            t["fingerprint"] = utls
        ss["tlsSettings"] = t
    elif tls == "reality":
        ss["security"] = "reality"
        r = {"publicKey": _s(n, "pbk"), "shortId": _s(n, "sid"),
             "fingerprint": utls or "chrome"}
        if sni:
            r["serverName"] = sni.split(",")[0]
        ss["realitySettings"] = r

    return ss


# reality 必须有非空 publicKey，否则 xray 报 empty "password"。
# 这与 formats.py 的 _reality_exportable 判定一致 —— 那边是导出时丢弃，
# 这边是测活前丢弃，两处都要有：能测通但导不出、或能导出但测不了都是浪费。
def _reality_ok(n):
    if str(n.get("tls") or "").lower() != "reality":
        return True
    return bool(str(n.get("pbk") or "").strip())


# xtls-rprx-origin / -direct 是早期 XTLS 流控，xray 已只支持 xtls-rprx-vision
VALID_FLOWS = {"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}


def to_outbound(n, tag):
    """节点 dict → xray outbound；不支持的返回 None"""
    p = n["proto"]
    try:
        n = dict(n, port=int(n["port"]))
    except (KeyError, TypeError, ValueError):
        return None
    # 前置拦掉确定非法的，避免进配置后靠 drop_bad_outbounds 逐个试探
    if not _reality_ok(n):
        return None
    if str(n.get("flow") or "").strip() not in VALID_FLOWS:
        return None
    if str(n.get("net") or "").lower() in ("none",):
        return None
    try:
        if p == "vmess":
            ob = {"protocol": "vmess", "settings": {"vnext": [{
                "address": n["addr"], "port": n["port"],
                "users": [{"id": n["id"], "alterId": n.get("aid", 0),
                           "security": n.get("scy") or "auto"}]}]}}
        elif p == "vless":
            user = {"id": n["id"], "encryption": "none"}
            if n.get("flow"):
                user["flow"] = n["flow"]
            ob = {"protocol": "vless", "settings": {"vnext": [{
                "address": n["addr"], "port": n["port"], "users": [user]}]}}
        elif p == "trojan":
            ob = {"protocol": "trojan", "settings": {"servers": [{
                "address": n["addr"], "port": n["port"], "password": n["id"]}]}}
        elif p == "ss":
            method = _s(n, "method").lower()
            if method not in SS_CIPHERS:
                return None
            ob = {"protocol": "shadowsocks", "settings": {"servers": [{
                "address": n["addr"], "port": n["port"],
                "method": method, "password": n["password"]}]}}
        else:
            return None
    except KeyError:
        return None

    ss = _stream_settings(n)
    if ss is None:
        return None  # 传输层不受支持，整个节点必须丢弃（不能退回明文 tcp）
    if ss.get("network") != "tcp" or "security" in ss or "tcpSettings" in ss:
        ob["streamSettings"] = ss
    ob["tag"] = tag
    return ob


def config_ok(cfg, tag="test"):
    """用 xray -test 预校验。单个非法 outbound 就会让整批加载失败，
    因此必须在启动前确认，并能定位到具体是哪个 tag。"""
    TEMP.mkdir(exist_ok=True)
    path = TEMP / f"xray_{tag}_test.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    # 显式 UTF-8：节点名含中文/emoji，默认编码在两个平台上都可能抛解码错
    r = subprocess.run([str(XRAY), "run", "-test", "-c", str(path)],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=90,
                       creationflags=_NO_WINDOW)
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        if "Failed to start" in line:
            return False, line.strip()
    return r.returncode == 0, ""


def drop_bad_outbounds(nodes, tag="scrub", _depth=0):
    """反复 -test，把导致加载失败的 outbound 摘掉，直到整批配置合法。
    单节点重试代价太高，靠错误信息里的 tag 精确定位。

    xray 一次只报第一个坏 tag（实测：30 个坏节点要 31 次 -test 才收敛），
    所以只能逐个摘。上限设为节点数 + 余量，而不是固定 60 —— 曾因固定 60
    在坏节点占半数时耗尽，且**耗尽后返回的仍是非法列表**，导致 start_xray
    必然失败、整批 100 个候选作废（实测 60 批里 41 批如此）。

    耗尽或无法定位时不再返回非法列表，改为二分递归：把批拆成两半各自
    净化。这样最坏情况下也只损失真正有问题的那一小块，而不是整批。
    """
    import re
    cur = list(nodes)
    dropped = 0
    # 上限给到节点数 +10：坏节点最多也就是全部，留点余量给重复定位
    limit = len(cur) + 10
    for _ in range(limit):
        cfg, mapping = build_config(cur)
        if not mapping:
            return []
        ok, err = config_ok(cfg, tag)
        if ok:
            if dropped:
                print(f"    摘除 {dropped} 个不兼容节点（剩 {len(cur)}）")
            return cur
        m = re.search(r"tag out(\d+)", err)
        if not m:
            # 定位不到（错误没带 tag，比如 ss2022 密码解码失败发生在
            # server 构建阶段）→ 二分拆分，别整批丢
            return _split_scrub(cur, tag, err, _depth)
        # tag outN 的 N 是 mapping 下标（build_config 已跳过不可转换项），
        # 必须映射回 cur 中的实际节点再删，否则下标随删除而错位
        bad_node = mapping[int(m.group(1))][1]
        cur = [n for n in cur if n is not bad_node]
        dropped += 1
    # 理论上到不了这里（limit 已覆盖全部节点），兜底也走二分
    return _split_scrub(cur, tag, "迭代耗尽", _depth)


def _split_scrub(nodes, tag, err, depth):
    """二分净化：把批拆两半分别净化，避免因一个定位不到的坏节点丢掉整批。"""
    if len(nodes) <= 1:
        # 单个节点仍非法 → 只丢它一个
        print(f"    丢弃 1 个无法定位的坏节点: {str(err).split('> ')[-1][:70]}")
        return []
    if depth >= 8:  # 2^8 = 256，足够覆盖任何批大小
        print(f"    二分过深，放弃 {len(nodes)} 个节点")
        return []
    mid = len(nodes) // 2
    left = drop_bad_outbounds(nodes[:mid], f"{tag}L", depth + 1)
    right = drop_bad_outbounds(nodes[mid:], f"{tag}R", depth + 1)
    return left + right


def build_config(batch, base_port=BASE_PORT):
    """batch: [(port_offset, node)] → (config dict, [(port, node)])"""
    inbounds, outbounds, rules, mapping = [], [], [], []
    for i, n in enumerate(batch):
        tag_in, tag_out = f"in{i}", f"out{i}"
        ob = to_outbound(n, tag_out)
        if ob is None:
            continue
        port = base_port + i
        inbounds.append({
            "tag": tag_in, "listen": "127.0.0.1", "port": port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
            "sniffing": {"enabled": False},
        })
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [tag_in], "outboundTag": tag_out})
        mapping.append((port, n))

    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds or [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    return cfg, mapping


def port_ready(port, timeout=0.3):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_ports_free(ports, timeout=15):
    """等端口段彻底释放。批次间复用端口时，旧进程未退干净会让新进程
    静默启动失败，而 port_ready 又把旧监听误判成'新进程已就绪'。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not any(port_ready(p, timeout=0.1) for p in ports):
            return True
        time.sleep(0.3)
    return False


def start_xray(cfg, tag="batch"):
    """写配置并启动 xray，等首个端口就绪。返回 (Popen, cfg_path)"""
    TEMP.mkdir(exist_ok=True)
    path = TEMP / f"xray_{tag}.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")

    ports = [ib["port"] for ib in cfg.get("inbounds", [])]
    if ports and not wait_ports_free(ports[:1] + ports[-1:]):
        raise RuntimeError(f"端口 {ports[0]}~{ports[-1]} 未释放，跳过该批")

    # xray 把致命错误写到 stdout，两路都要收，否则启动失败时拿不到原因
    proc = subprocess.Popen(
        [str(XRAY), "run", "-c", str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=_NO_WINDOW,
    )

    first = cfg["inbounds"][0]["port"] if cfg["inbounds"] else None
    if first:
        for _ in range(100):  # 最多等 10s
            if port_ready(first):
                break
            if proc.poll() is not None:
                err = proc.stdout.read().decode("utf-8", "ignore")
                fatal = [l for l in err.splitlines() if "Failed to start" in l]
                raise RuntimeError(f"xray 启动失败: {fatal or err[-500:]}")
            time.sleep(0.1)
    time.sleep(0.4)  # 给余下入站留出监听时间

    # 端口就绪 ≠ 进程健康（可能是残留监听），显式复核
    if proc.poll() is not None:
        err = proc.stdout.read().decode("utf-8", "ignore")
        fatal = [l for l in err.splitlines() if "Failed to start" in l]
        raise RuntimeError(f"xray 启动后退出: {fatal or err[-300:]}")
    return proc, path


def stop_xray(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
