import sys
import os
import requests
import json
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
from colorama import Fore, Style, init
from logging import getLogger
import numpy as np
from scapy.all import Ether, sniff, IP, TCP, UDP, IPv6, conf as scapy_conf
from transformers import AutoTokenizer, AutoModelForCausalLM
import configparser
import time
import threading
import queue
import torch
import torch.nn as nn
from datetime import datetime
import sqlite3
import ctypes


LLM_MODEL_ID = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
llm_tokenizer = None
llm_model = None


try:
    import pynvml
    pynvml.nvmlInit()
    HAS_GPU_MONITOR = True
except:
    HAS_GPU_MONITOR = False

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn


from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align

sys.path.append("util")
VERBOSE = False

from arg_utils import get_base_parser, update_parser
from model_utils import check_and_download_models

init(autoreset=True)
console = Console()
print_lock = threading.Lock()


config = configparser.ConfigParser()
config.read('config.ini')
BOT_TOKEN = config['Notifications']['BOT_TOKEN']
ALERT_COOLDOWN = float(config['Notifications']['ALERT_COOLDOWN'])
CHANNEL_ID = config['Notifications']['CHANNEL_ID']
WEIGHT_PATH = config['Model']['WEIGHT_PATH']
MODEL_PATH = config['Model']['MODEL_PATH']
REMOTE_PATH = config['Model']['REMOTE_PATH']


stats_lock = threading.Lock()
stats = {
    "total_packets": 0, 
    "alerts": 0, 
    "start_time": time.time(), 
    "pps": 0,
    "alert_history": [],
    "recent_packets": [],
    "batch_processed": 0,
    "gpu_info": {"load": 0, "temp": 0, "mem_used": 0, "mem_total": 0, "name": "N/A"},
    "anomaly_score": 0.0,
    "anomaly_status": "Calculating...",
    "system_status": "Initializing..."
}
packet_queue = queue.Queue(maxsize=10000)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

try:
    BATCH_SIZE = int(config.get('Performance', 'BATCH_SIZE', fallback=32))
    THROTTLE_DELAY = float(config.get('Performance', 'THROTTLE_DELAY', fallback=0.05))
except:
    BATCH_SIZE = 32
    THROTTLE_DELAY = 0.05

LABELS = [
    "Analysis", "Backdoor", "Bot", "DDoS", "DoS", "DoS GoldenEye", "DoS Hulk", "DoS SlowHTTPTest", "DoS Slowloris", 
    "Exploits", "FTP Patator", "Fuzzers", "Generic", "Heartbleed", "Infiltration", "Normal", "Port Scan", "Reconnaissance", 
    "SSH Patator", "Shellcode", "Web Attack - Brute Force", "Web Attack - SQL Injection", "Web Attack - XSS", "Worms",
]


def init_db():
    conn = sqlite3.connect('nethawk_logs.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, label TEXT, src_ip TEXT, dst_ip TEXT, score REAL)''')
    conn.commit()
    return conn

db_conn = init_db()

class AnomalyGuard(nn.Module):
    def __init__(self):
        super(AnomalyGuard, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(8, 4), nn.ReLU(),
            nn.Linear(4, 2), nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(2, 4), nn.ReLU(),
            nn.Linear(4, 8)
        )
        self.register_buffer("threshold", torch.tensor(1.0))
        self.register_buffer("mean_score", torch.tensor(0.5))
        self.warmup_count = 0
        self.MAX_WARMUP = 100 
    def forward(self, x): return self.decoder(self.encoder(x))
    def update_threshold(self, score):
        self.mean_score = 0.99 * self.mean_score + 0.01 * score
        self.threshold = self.mean_score * 3.0 

def alert(label, score, src_ip, dst_ip, severity="high"):
    title = "🚨 Attack Detected!" if severity == "high" else "⚠️ Possible Attack!"
    color = 16711680 if severity == "high" else 16776960
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c = db_conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, label, src_ip, dst_ip, score) VALUES (?, ?, ?, ?, ?)", 
              (timestamp, label, src_ip, dst_ip, float(score)))
    db_id = c.lastrowid
    db_conn.commit()

    def notify():
        if not BOT_TOKEN or not CHANNEL_ID or "YOUR_" in BOT_TOKEN: return
        url = f"https://discord.com/api/v10/channels/{CHANNEL_ID.strip()}/messages"
        headers = {"Authorization": f"Bot {BOT_TOKEN.strip()}", "Content-Type": "application/json"}
        try: requests.post(url, json={"embeds":[{"title": title, "description": f"🧩 Type: {label}\n📊 Score: {score*100:.2f}%\n🌐 From: `{src_ip}`\n🎯 To: `{dst_ip}`", "color": color}]}, headers=headers)
        except: pass
    threading.Thread(target=notify, daemon=True).start()
    
    with stats_lock:
        recent_alerts = [a for a in stats["alert_history"] if a["label"] == label and a["src"] == src_ip]
        if len(recent_alerts) > 5: return 

        stats["alert_history"].append({"id": db_id, "time": timestamp.split()[-1], "label": label, "src": src_ip, "dst": dst_ip, "score": float(score)})
        if len(stats["alert_history"]) > 30: stats["alert_history"].pop(0)
        stats["alerts"] += 1

def get_entropy(data):
    if not data: return 0
    import math
    from collections import Counter
    counts = Counter(data)
    len_data = len(data)
    return -sum((count / len_data) * math.log2(count / len_data) for count in counts.values())

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        try: return os.getuid() == 0
        except: return False

def preprocess_batch(packet_hex_list):
    processed = []
    valid_indices = []
    for i, hex_str in enumerate(packet_hex_list):
        try:
            packet_bytes = bytes.fromhex(hex_str)
            packet = Ether(packet_bytes) if len(packet_bytes) > 14 else None
            if not packet: continue
            
            ip_layer = None
            if "IP" in packet: ip_layer = packet["IP"]
            elif "IPv6" in packet: ip_layer = packet["IPv6"]
            if not ip_layer: continue
            
            is_tcp, is_udp = "TCP" in packet, "UDP" in packet
            if not is_tcp and not is_udp: continue
            
            trans = packet["TCP"] if is_tcp else packet["UDP"]
            payload = bytes(ip_layer.payload)[:300]
            tcp_ofs = trans.dataofs if is_tcp else 0
            tcp_flags = int(trans.flags) if is_tcp else 0
            
            ttl = getattr(ip_layer, 'ttl', getattr(ip_layer, 'hlim', 64))
            tos = getattr(ip_layer, 'tos', getattr(ip_layer, 'tc', 0))
            ip_len = len(ip_layer)
            
            feats = [-1, -1, len(packet_bytes), -1, trans.sport, trans.dport, ip_len, len(payload), ttl, tos, tcp_ofs, tcp_flags, -1]
            fmt = " ".join(map(str, feats)) + " " + " ".join(map(str, payload))
            processed.append(fmt[:1024])
            valid_indices.append(i)
        except: continue
    return processed, valid_indices

def predict_batch(models, packets_list):
    hex_list = [bytes(p).hex() for p in packets_list]
    fmt_list, valid_idx = preprocess_batch(hex_list)
    if not fmt_list: return []
    m_in = models["tokenizer"](fmt_list, padding=True, truncation=True, max_length=1024, return_tensors="np")
    out = models["net"].run(None, {"input_ids": m_in.input_ids, "attention_mask": m_in.attention_mask})
    results = []
    for i, logits in enumerate(out[0]):
        scores = torch.nn.functional.softmax(torch.tensor(logits), dim=0).numpy()
        idx = np.argsort(-scores)
        results.append((valid_idx[i], np.array(LABELS)[idx], scores[idx]))
    return results

app = FastAPI()
@app.get("/api/stats")
def get_api_stats():
    with stats_lock:
        return {
            "uptime": int(time.time() - stats["start_time"]),
            "total_packets": stats["total_packets"],
            "pps": stats["pps"],
            "alerts": stats["alerts"],
            "device": str(DEVICE),
            "gpu": stats["gpu_info"],
            "anomaly": {"score": stats["anomaly_score"], "status": stats["anomaly_status"]},
            "system_status": stats["system_status"]
        }

@app.get("/api/alerts")
def get_api_alerts():
    with stats_lock: return stats["alert_history"]

@app.get("/api/analyze/{alert_id}")
async def analyze_threat(alert_id: int):
    c = db_conn.cursor()
    c.execute("SELECT label, score, src_ip, dst_ip FROM alerts WHERE id = ?", (alert_id,))
    row = c.fetchone()
    if not row: return {"error": "Alert not found"}
    label, score, src, dst = row
    if not llm_model: return {"advice": "AI Advisor is starting up... Please try again in a few seconds."}
    prompt = f"<|system|>\nYou are a Cybersecurity Expert. Analyze this network alert and provide a short, professional advice (30-50 words).\n<|user|>\nAlert: {label}\nConfidence: {score*100:.2f}%\nSource: {src}\nTarget: {dst}\nAdvice:\n<|assistant|>\n"
    inputs = llm_tokenizer(prompt, return_tensors="pt").to(DEVICE)
    with torch.no_grad():
        outputs = llm_model.generate(**inputs, max_new_tokens=100, do_sample=True, temperature=0.7)
    advice = llm_tokenizer.decode(outputs[0], skip_special_tokens=True).split("<|assistant|>")[-1].strip()
    return {"advice": advice}

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NetHawk Web Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Outfit', sans-serif; background: #0f172a; color: #f1f5f9; }
            .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.1); }
            .glow-red { box-shadow: 0 0 20px rgba(239, 68, 68, 0.3); }
            .glow-cyan { box-shadow: 0 0 20px rgba(34, 211, 238, 0.3); }
            @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
            .pulse { animation: pulse 2s infinite; }
            .gpu-bar { transition: width 0.5s ease-in-out; }
        </style>
    </head>
    <body class="p-8">
        <div class="max-w-7xl mx-auto">
            <header class="flex justify-between items-center mb-8 glass p-6 rounded-3xl glow-cyan">
                <div>
                    <h1 class="text-4xl font-bold text-cyan-400">🦅 NETHAWK <span class="text-white font-light text-xl">AI-DRIVEN IPS</span></h1>
                    <p class="text-slate-400">Cyber-Threat Detection & Real-time Analysis</p>
                </div>
                <div class="text-right">
                    <div id="uptime" class="text-sm text-slate-400">UPTIME: 0s</div>
                    <div id="device_name" class="text-xs text-cyan-500 font-mono">DEVICE: N/A</div>
                </div>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <div class="glass p-6 rounded-3xl border-l-4 border-cyan-500">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase font-bold">Total Traffic</h3>
                    <div id="total_packets" class="text-4xl font-bold">0</div>
                    <div id="pps" class="text-cyan-400 text-sm mt-2 font-mono">0 PPS</div>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-red-500 glow-red">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase font-bold">Threats</h3>
                    <div id="alerts_count" class="text-4xl font-bold text-red-500">0</div>
                    <div class="text-red-400 text-sm mt-2 pulse">🔴 MONITORING LIVE</div>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-purple-500">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase font-bold">GPU LOAD</h3>
                    <div id="gpu_load" class="text-4xl font-bold text-purple-400">0%</div>
                    <div class="w-full bg-slate-800 rounded-full h-1.5 mt-3">
                        <div id="gpu_bar" class="gpu-bar bg-purple-500 h-1.5 rounded-full" style="width: 0%"></div>
                    </div>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-orange-500">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase font-bold">GPU TEMP</h3>
                    <div id="gpu_temp" class="text-4xl font-bold text-orange-400">0°C</div>
                    <div id="gpu_mem" class="text-slate-400 text-xs mt-2 font-mono">MEM: 0 / 0 MB</div>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div class="glass p-6 rounded-3xl border-l-4 border-yellow-500 col-span-1">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase font-bold">Anomaly Score</h3>
                    <div id="anomaly_score" class="text-4xl font-bold text-yellow-500">0.0</div>
                    <div id="anomaly_status" class="text-slate-400 text-sm mt-2 font-mono uppercase">STATUS: NORMAL</div>
                </div>
                <div class="glass p-6 rounded-3xl col-span-2">
                    <h3 class="text-xl font-bold mb-4 flex items-center"><span class="w-3 h-3 bg-red-500 rounded-full mr-2 pulse"></span>Live Threat Intelligence</h3>
                    <div class="overflow-x-auto max-h-[400px]">
                        <table class="w-full text-left">
                            <thead>
                                <tr class="text-slate-400 border-b border-slate-700">
                                    <th class="pb-3 font-semibold">TIMESTAMP</th>
                                    <th class="pb-3 font-semibold">TYPE</th>
                                    <th class="pb-3 font-semibold">SOURCE</th>
                                    <th class="pb-3 font-semibold text-right">SCORE</th>
                                </tr>
                            </thead>
                            <tbody id="alert_table" class="text-sm"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div id="aiModal" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
            <div class="glass max-w-2xl w-full p-8 rounded-3xl glow-cyan">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-2xl font-bold text-cyan-400">🤖 AI Security Advisor</h2>
                    <button onclick="closeModal()" class="text-slate-400 hover:text-white">✕</button>
                </div>
                <div id="aiContent" class="text-slate-300 leading-relaxed italic">Analyzing threat patterns...</div>
                <div class="mt-8 flex justify-end"><button onclick="closeModal()" class="bg-cyan-600 hover:bg-cyan-500 text-white px-6 py-2 rounded-xl font-bold">Close Advisor</button></div>
            </div>
        </div>

        <script>
            async function showAI(id) {
                document.getElementById('aiModal').classList.remove('hidden');
                document.getElementById('aiContent').innerHTML = '<div class="pulse">🧠 Thinking... Generating security strategy...</div>';
                try {
                    const res = await fetch(`/api/analyze/${id}`);
                    const data = await res.json();
                    document.getElementById('aiContent').innerText = data.advice || data.error;
                } catch (e) { document.getElementById('aiContent').innerText = "Error connecting to AI Advisor."; }
            }
            function closeModal() { document.getElementById('aiModal').classList.add('hidden'); }

            async function updateStats() {
                try {
                    const res = await fetch('/api/stats');
                    const data = await res.json();
                    document.getElementById('total_packets').innerText = data.total_packets.toLocaleString();
                    document.getElementById('pps').innerText = data.pps + ' PPS';
                    document.getElementById('alerts_count').innerText = data.alerts;
                    document.getElementById('uptime').innerText = 'UPTIME: ' + data.uptime + 's';
                    document.getElementById('anomaly_score').innerText = data.anomaly.score.toFixed(4);
                    document.getElementById('anomaly_status').innerText = 'STATUS: ' + data.anomaly.status;
                    
                    const deviceEl = document.getElementById('device_name');
                    if (data.gpu && data.gpu.name !== "N/A") {
                        deviceEl.innerText = 'ACCELERATION: ' + data.gpu.name;
                        document.getElementById('gpu_load').innerText = data.gpu.load + '%';
                        document.getElementById('gpu_bar').style.width = data.gpu.load + '%';
                        document.getElementById('gpu_temp').innerText = data.gpu.temp + '°C';
                        document.getElementById('gpu_mem').innerText = 'MEM: ' + data.gpu.mem_used + ' / ' + data.gpu.mem_total + ' MB';
                    } else {
                        deviceEl.innerText = 'ACCELERATION: CPU MODE';
                        document.getElementById('gpu_load').innerText = 'N/A';
                    }

                    if (data.system_status && data.system_status !== "Ready") {
                        document.getElementById('uptime').innerHTML = `<span class='pulse text-yellow-400'>⏳ ${data.system_status}</span>`;
                    }
                } catch (e) {}
            }

            async function updateAlerts() {
                try {
                    const res = await fetch('/api/alerts');
                    const data = await res.json();
                    const table = document.getElementById('alert_table');
                    table.innerHTML = data.slice().reverse().map(a => `
                        <tr class="border-b border-slate-800/50 hover:bg-slate-800/30 transition-all">
                            <td class="py-4 font-mono text-slate-400">${a.time}</td>
                            <td class="py-4"><span class="bg-red-500/20 text-red-400 px-3 py-1 rounded-full text-xs font-bold border border-red-500/30">${a.label}</span></td>
                            <td class="py-4 text-slate-300">${a.src}</td>
                            <td class="py-4 text-right">
                                <span class="font-bold text-red-500 mr-4">${(a.score * 100).toFixed(1)}%</span>
                                <button onclick="showAI(${a.id})" class="bg-cyan-600/20 hover:bg-cyan-600/40 text-cyan-400 text-[10px] px-2 py-1 rounded border border-cyan-500/30">AI ADVISE</button>
                            </td>
                        </tr>
                    `).join('');
                } catch (e) {}
            }

            setInterval(updateStats, 1000);
            setInterval(updateAlerts, 2000);
            updateStats(); updateAlerts();
        </script>
    </body>
    </html>
    """

def create_layout() -> Layout:
    layout = Layout()
    layout.split_column(Layout(name="header", size=3), Layout(name="body"), Layout(name="footer", size=3))
    layout["body"].split_row(Layout(name="left", ratio=1), Layout(name="right", ratio=2))
    return layout

class Header:
    def __rich__(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1); grid.add_column(justify="center", ratio=1); grid.add_column(justify="right", ratio=1)
        grid.add_row("[bold cyan]🦅 NETHAWK AI-IPS[/bold cyan]", "[bold yellow]WEB DASHBOARD: http://127.0.0.1:8000[/bold yellow]", datetime.now().ctime())
        return Panel(grid, style="cyan")

class Footer:
    def __rich__(self) -> Panel:
        with stats_lock:
            uptime, pps, total, batches = int(time.time() - stats["start_time"]), stats["pps"], stats["total_packets"], stats["batch_processed"]
        grid = Table.grid(expand=True); grid.add_column(justify="left", ratio=1)
        grid.add_row(f"[bold green]UPTIME:[/bold green] {uptime}s | [bold green]PPS:[/bold green] {pps} | [bold green]TOTAL:[/bold green] {total} | [bold green]BATCHES:[/bold green] {batches}")
        return Panel(grid, style="green")

def get_stats_panel():
    with stats_lock: alerts_count, gpu = stats["alerts"], stats["gpu_info"]
    table = Table.grid(padding=1); table.add_column(style="bold magenta", justify="right"); table.add_column(style="bold white")
    table.add_row("ALERTS", str(alerts_count)); table.add_row("GPU LOAD", f"{gpu['load']}%"); table.add_row("GPU TEMP", f"{gpu['temp']}°C"); table.add_row("GPU MEM", f"{gpu['mem_used']}/{gpu['mem_total']}MB"); table.add_row("WEB SERVER", "[bold green]ONLINE[/bold green]")
    return Panel(Align.center(table, vertical="middle"), title="System Stats", border_style="magenta")

def get_alert_table():
    table = Table(title="[bold red]LIVE THREAT TICKER[/bold red]", expand=True, border_style="red")
    table.add_column("Time", style="dim"); table.add_column("Type", style="bold red"); table.add_column("Source IP"); table.add_column("Score", justify="right")
    with stats_lock:
        for a in reversed(stats["alert_history"][-10:]): table.add_row(a["time"], a["label"], a["src"], f"{a['score']*100:.1f}%")
    return table

def get_packet_table():
    table = Table(title="[bold blue]BATCH PACKET MONITOR[/bold blue]", expand=True, border_style="blue")
    table.add_column("Source IP"); table.add_column("Destination IP"); table.add_column("Prediction", style="bold"); table.add_column("Conf.", justify="right")
    with stats_lock:
        for p in reversed(stats["recent_packets"][-20:]):
            style = "green" if p["label"] == "Normal" else "yellow" if p["score"] < 0.8 else "bold red"
            table.add_row(p["src"], p["dst"], f"[{style}]{p['label']}[/{style}]", f"{p['score']*100:.1f}%")
    return table

if __name__ == "__main__":
    try:
        parser = get_base_parser("NetHawk Packet Analyzer", "input_hex.txt", None)
        parser.add_argument("--iface", type=str, help="Network Interface")
        parser.add_argument("--filter", type=str, help="Scapy Filter")
        parser.add_argument("--verbose", action="store_true", help="Show details")
        args = update_parser(parser); VERBOSE = args.verbose
        
        hf_token = config.get('Model', 'HF_TOKEN', fallback=os.environ.get("HF_TOKEN"))
        if not hf_token:
            try:
                print(f"{Fore.YELLOW}🔑 Optional: Enter HuggingFace Token (HF_TOKEN) to avoid rate limits (Press Enter to skip):")
                hf_token = input("> ").strip()
                if hf_token:
                    os.environ["HF_TOKEN"] = hf_token
                    if 'Model' not in config.sections(): config.add_section('Model')
                    config.set('Model', 'HF_TOKEN', hf_token)
                    with open('config.ini', 'w') as configfile: config.write(configfile)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}👋 Exit requested during setup.")
                sys.exit(0)
        else:
            os.environ["HF_TOKEN"] = hf_token

        def run_web():
            uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error", access_log=False)
        threading.Thread(target=run_web, daemon=True).start()

        with stats_lock: stats["system_status"] = "Detecting Network..."
        iface = args.iface
        from scapy.all import get_if_list, get_if_addr
        interfaces = get_if_list()
        if iface and iface.isdigit():
            try:
                from scapy.arch.windows import get_windows_if_list
                win_ifs = get_windows_if_list()
                for w in win_ifs:
                    if str(w.get('pcap_index')) == iface or str(w.get('index')) == iface:
                        iface = w['name']; break
            except: pass

        if not iface:
            if sys.platform.startswith('win'):
                try:
                    from scapy.arch.windows import get_windows_if_list
                    win_ifs = get_windows_if_list()
                    ether_keywords = ["realtek", "gbe", "pci", "ethernet", "lan", "family controller", "gigabit"]
                    ignore_keywords = ["virtual", "hyper-v", "miniport", "loopback", "bluetooth", "wi-fi", "wireless", "wlan", "software"]
                    best_score = -999
                    for w in win_ifs:
                        desc, name = w.get('description', '').lower(), w.get('name', '').lower()
                        try:
                            ips = w.get('ips', [])
                            if not ips: continue
                            has_active_ip = False
                            for addr in ips:
                                if addr != "0.0.0.0" and not addr.startswith("169.254") and addr != "127.0.0.1":
                                    has_active_ip = True; break
                            if not has_active_ip: continue
                            score = 0
                            if any(k in desc for k in ether_keywords): score += 30
                            if any(k in name for k in ether_keywords): score += 15
                            if any(k in desc for k in ignore_keywords): score -= 100
                            if any(k in name for k in ignore_keywords): score -= 100
                            score += len(ips) * 2
                            if score > best_score: best_score = score; iface = w['name']
                        except: continue
                except: pass
            if not iface: iface = scapy_conf.iface 

        if not is_admin(): print(f"{Fore.RED}⚠️ WARNING: Not running as Administrator.")
        if sys.platform.startswith('win'):
            if not scapy_conf.use_pcap:
                print(f"{Fore.RED}❌ ERROR: Npcap/WinPcap not detected!")
            else:
                print(f"{Fore.GREEN}✅ Packet Capture Driver: Found")

        try:
            current_ip = get_if_addr(iface)
            print(f"{Fore.CYAN}🔍 Auto-Detected Interface: {iface} ({current_ip})")
        except: print(f"{Fore.YELLOW}⚠️ Warning: Could not determine IP for {iface}")

        with stats_lock: stats["system_status"] = "Downloading Models..."
        check_and_download_models(WEIGHT_PATH, MODEL_PATH, REMOTE_PATH)
        with stats_lock: stats["system_status"] = "Loading TinyLlama AI..."
        print(f"{Fore.CYAN}🚀 Loading AI Security Advisor...")
        llm_tokenizer = AutoTokenizer.from_pretrained(LLM_MODEL_ID)
        llm_model = AutoModelForCausalLM.from_pretrained(LLM_MODEL_ID, torch_dtype=torch.float16).to(DEVICE)
        print(f"{Fore.GREEN}✅ AI Security Advisor Ready!")
        with stats_lock: stats["system_status"] = "Initializing Core AI..."
        import onnxruntime
        try: net = onnxruntime.InferenceSession(WEIGHT_PATH, providers=['CUDAExecutionProvider', 'CPUExecutionProvider'])
        except: net = onnxruntime.InferenceSession(WEIGHT_PATH)
        models = {"tokenizer": AutoTokenizer.from_pretrained("tokenizer"), "net": net, "guard": AnomalyGuard().to(DEVICE)}
        
        def worker():
            while True:
                batch_packets = []
                try:
                    try:
                        for _ in range(BATCH_SIZE): batch_packets.append(packet_queue.get(timeout=0.1))
                    except queue.Empty: pass
                    if not batch_packets: continue
                    results = predict_batch(models, batch_packets)
                    for idx, labels, scores in results:
                        p = batch_packets[idx]
                        ip_src = p["IP"].src if "IP" in p else p["IPv6"].src
                        ip_dst = p["IP"].dst if "IP" in p else p["IPv6"].dst
                        top_label, top_score = labels[0], scores[0]
                        with stats_lock:
                            stats["recent_packets"].append({"src": ip_src, "dst": ip_dst, "label": top_label, "score": top_score})
                            if len(stats["recent_packets"]) > 40: stats["recent_packets"].pop(0)
                        if top_label != "Normal" and top_score > 0.8: alert(top_label, top_score, ip_src, ip_dst)
                    with stats_lock:
                        stats["total_packets"] += len(batch_packets)
                        stats["batch_processed"] += 1
                    for _ in range(len(batch_packets)): packet_queue.task_done()
                    try:
                        feat_list = []
                        for p in batch_packets:
                            sport, dport, proto = 0, 0, 0
                            if "TCP" in p: sport, dport, proto = p[TCP].sport, p[TCP].dport, 6
                            elif "UDP" in p: sport, dport, proto = p[UDP].sport, p[UDP].dport, 17
                            ip_layer = p["IP"] if "IP" in p else p["IPv6"] if "IPv6" in p else None
                            ttl, payload = getattr(ip_layer, 'ttl', 64), bytes(ip_layer.payload) if ip_layer else b""
                            feat_list.append([len(p)/1500.0, sport/65535.0, dport/65535.0, ttl/255.0, proto/255.0, get_entropy(payload)/8.0, len(payload)/1500.0, 1.0 if "TCP" in p and p[TCP].flags else 0.0])
                        feat_tensor = torch.tensor(feat_list, dtype=torch.float32).to(DEVICE)
                        with torch.no_grad():
                            recon = models["guard"](feat_tensor)
                            loss = torch.mean((recon - feat_tensor)**2, dim=1); avg_loss = torch.mean(loss).item()
                        with stats_lock:
                            stats["anomaly_score"] = avg_loss
                            if avg_loss > models["guard"].threshold.item() and avg_loss > 0.05:
                                stats["anomaly_status"] = "CRITICAL"
                                p_anom = batch_packets[torch.argmax(loss).item()]
                                ip_src, ip_dst = (p_anom["IP"].src, p_anom["IP"].dst) if "IP" in p_anom else (p_anom["IPv6"].src, p_anom["IPv6"].dst)
                                alert("Zero-Day Anomaly", avg_loss, ip_src, ip_dst, severity="medium")
                            else:
                                stats["anomaly_status"] = "NORMAL"
                                if avg_loss > 0: models["guard"].update_threshold(avg_loss)
                    except: pass
                    if THROTTLE_DELAY > 0: time.sleep(THROTTLE_DELAY)
                except Exception as e:
                    if VERBOSE: print(f"Worker Error: {e}")
        threading.Thread(target=worker, daemon=True).start()

        with stats_lock: stats["system_status"] = "Ready"

        def stats_updater():
            last_count = 0
            while True:
                time.sleep(1)
                with stats_lock:
                    stats["pps"] = stats["total_packets"] - last_count
                    last_count = stats["total_packets"]
                if HAS_GPU_MONITOR:
                    try:
                        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                        util, temp, mem, name = pynvml.nvmlDeviceGetUtilizationRates(handle), pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU), pynvml.nvmlDeviceGetMemoryInfo(handle), pynvml.nvmlDeviceGetName(handle)
                        if isinstance(name, bytes): name = name.decode('utf-8')
                        with stats_lock: stats["gpu_info"] = {"load": util.gpu, "temp": temp, "mem_used": mem.used // (1024**2), "mem_total": mem.total // (1024**2), "name": name}
                    except: pass
        threading.Thread(target=stats_updater, daemon=True).start()

        sniff_error = None
        def packet_callback(p):
            if "IP" in p or "IPv6" in p: packet_queue.put(p)
        
        def run_sniff():
            global sniff_error
            try:
                sniff(prn=packet_callback, filter="(ip or ip6) and (tcp or udp)", iface=iface, store=0)
            except Exception as e:
                sniff_error = str(e)

        print(f"{Fore.YELLOW}📡 Sniffing started on {iface}...")
        threading.Thread(target=run_sniff, daemon=True).start()

        layout = create_layout()
        with Live(layout, refresh_per_second=4, screen=True) as live:
            while True:
                if sniff_error:
                    raise RuntimeError(f"Sniffing thread failed: {sniff_error}")
                layout["header"].update(Header()); layout["footer"].update(Footer()); layout["left"].update(get_stats_panel()); layout["right"].split_column(Layout(get_packet_table(), ratio=3), Layout(get_alert_table(), ratio=1))
                time.sleep(0.2)
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}🦅 NetHawk is shutting down... Goodbye!")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Critical Error: {e}")
    finally:
        try: db_conn.close()
        except: pass
        if HAS_GPU_MONITOR:
            try: pynvml.nvmlShutdown()
            except: pass
        sys.exit(0)
