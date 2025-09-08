import sys
import os
import requests
import json
from colorama import Fore, Style, init
from logging import getLogger
import numpy as np
from scapy.all import Ether, CookedLinux, sniff, IP, TCP
from transformers import AutoTokenizer
import ailia
import configparser
import time
import threading
util_path = "util"
sys.path.append(util_path)

from arg_utils import get_base_parser, update_parser
from model_utils import check_and_download_models
from math_utils import softmax

init(autoreset=True)
logger = getLogger(__name__)

config = configparser.ConfigParser()
config.read('config.ini')
BOT_TOKEN = config['Notifications']['BOT_TOKEN']
ALERT_COOLDOWN = float(config['Notifications']['ALERT_COOLDOWN'])
CHANNEL_ID = config['Notifications']['CHANNEL_ID']

WEIGHT_PATH = config['Model']['WEIGHT_PATH']
MODEL_PATH = config['Model']['MODEL_PATH']
REMOTE_PATH = config['Model']['REMOTE_PATH']

last_sent_time = 0
last_message_id = None
batch_alerts = []
BATCH_INTERVAL = 5 * 60


# ============================================================================================================================================================================================================================================================================
# labels meaning
# ============================================================================================================================================================================================================================================================================
# Analysis: Refers to the process of analyzing network traffic, vulnerabilities, or system logs to detect potential threats, incidents, or weaknesses in a system or application.
# Backdoor: A method of bypassing normal authentication procedures to gain unauthorized access to a system or network, often installed by attackers or malware.
# Bot: Refers to automated software (often malicious) used to perform repetitive tasks on the internet, often involved in botnets for activities like DDoS attacks.
# DDoS (Distributed Denial of Service): A type of attack that attempts to disrupt the normal traffic of a targeted server, service, or network by overwhelming it with a flood of internet traffic from multiple sources.
# DoS (Denial of Service): A type of cyberattack that aims to make a system or network unavailable by overwhelming it with traffic or exploiting vulnerabilities.
# DoS GoldenEye: A specific Denial of Service tool that targets web servers, particularly by simulating multiple client requests that exhaust the server’s resources.
# DoS Hulk: A Denial of Service attack tool designed to overload a server or website by using HTTP requests that aim to exhaust server resources quickly.
# DoS SlowHTTPTest: A testing tool used to simulate DoS attacks on web servers by sending slow HTTP requests to exhaust server resources.
# DoS Slowloris: A DoS attack tool designed to keep many connections to the target server open and hold them open as long as possible, using very slow HTTP requests to exhaust server resources.
# Exploits: Software or techniques that take advantage of vulnerabilities in a system, application, or service to perform unintended actions, such as gaining unauthorized access or executing arbitrary code.
# FTP Patator: A brute force attack tool for FTP (File Transfer Protocol), typically used to try different password combinations to gain unauthorized access to an FTP server.
# Fuzzers: Tools used to discover vulnerabilities in software by inputting random or unexpected data (fuzzing) to trigger crashes, memory leaks, or security flaws.
# Generic: A general category for vulnerabilities or attacks that don’t fall into any of the more specific categories listed. It may also refer to standard attack patterns or methods.
# Heartbleed: A critical vulnerability in the OpenSSL cryptographic software library that allows attackers to read sensitive data from the memory of affected systems. It was one of the most notorious security bugs in recent years.
# Infiltration: Refers to unauthorized access or entry into a network, system, or application, often through covert means, to steal data or carry out malicious activities.
# Normal: Refers to normal or non-malicious network traffic or activity that is expected and does not pose any security risk.
# Port Scan: A method used by attackers to detect open ports on a target system. Port scanning helps attackers identify vulnerable services and possible attack vectors.
# Reconnaissance: The process of gathering information about a target system, network, or environment to prepare for an attack, often through methods like scanning, enumeration, or OS fingerprinting.
# SSH Patator: A brute force tool used to perform automated SSH (Secure Shell) login attempts with different username and password combinations, often used in password cracking attacks.
# Shellcode: A small piece of code used as the payload in an exploit to initiate a command, often used for gaining control over a vulnerable system.
# Web Attack - Brute Force: A method of attacking web-based services or applications by attempting to guess login credentials through trial and error, often using automated tools.
# Web Attack - SQL Injection: A type of attack where the attacker exploits vulnerabilities in a web application's input handling to execute arbitrary SQL code on the backend database.
# Web Attack - XSS (Cross-Site Scripting): A vulnerability in web applications where malicious scripts are injected into web pages viewed by users, allowing attackers to execute scripts in the user's browser and potentially steal data or perform malicious actions.
# Worms: A type of malware that can replicate itself and spread across networks, often without user intervention, exploiting vulnerabilities in software or systems to infect other machines.


LABELS = [
    "Analysis", "Backdoor", "Bot", "DDoS", "DoS", "DoS GoldenEye", "DoS Hulk", "DoS SlowHTTPTest", "DoS Slowloris", 
    "Exploits", "FTP Patator", "Fuzzers", "Generic", "Heartbleed", "Infiltration", "Normal", "Port Scan", "Reconnaissance", 
    "SSH Patator", "Shellcode", "Web Attack - Brute Force", "Web Attack - SQL Injection", "Web Attack - XSS", "Worms",
]

PACKEt_HEX_PATH = "input_hex.txt"

parser = get_base_parser(
    "bert-network-packet-flow-header-payload",
    PACKEt_HEX_PATH,
    None,
)
parser.add_argument("--hex", type=str, default=None, help="Input-HEX data.")
parser.add_argument("--iface", type=str , help="Network Interface eg; wlan0 eth0 enp0s3")
parser.add_argument("--filter", type=str , help="Adjust the scope of packet capture")
parser.add_argument("--store", type=int , default=0 , help="Captured packets are stored in memory (as a list) and returned when the sniffing session is complete.")
parser.add_argument('--disable_ailia_tokenizer', action='store_true', help='disable ailia tokenizer.')
parser.add_argument("--rtd" , action='store_true' , help="Real-time packet detection and network threat analysis using AI")
parser.add_argument("--ip", action="store_true", help="Use IP layer as payload.")
parser.add_argument("--onnx", action="store_true", help="execute onnxruntime version.")
parser.add_argument("--verbose", action='store_true', help="Show detailed analysis and system processing information.")
args = update_parser(parser)

VERBOSE = args.verbose

def vprint(*messages):
    if VERBOSE:
        print(Fore.GREEN + "[VERBOSE]", *messages, Style.RESET_ALL)

# ======================
# Functions
# ======================
def recognize_from_packet(models):
    packet_hex = args.hex
    if packet_hex:
        args.input[0] = packet_hex

    for packet_path in args.input:
        if os.path.isfile(packet_path):
            vprint("Processing file:", packet_path)
            with open(packet_path, "r") as f:
                packet_hex = f.read()

        vprint("Start inference for packet...\n")
        if args.benchmark:
            vprint("BENCHMARK mode enabled")
            total_time_estimation = 0
            for i in range(args.benchmark_count):
                start = int(round(time.time() * 1000))
                output = predict(models, packet_hex)
                end = int(round(time.time() * 1000))
                estimation_time = end - start
                vprint(f"\tInference time for iteration {i}: {estimation_time} ms")
                if i != 0:
                    total_time_estimation += estimation_time
            vprint(f"\tAverage inference time: {total_time_estimation / (args.benchmark_count - 1)} ms")
        else:
            output = predict(models, packet_hex)

    top_k = 21
    labels, scores = output
    for label, score in list(zip(labels, scores))[:top_k]:
        print(f"{label} : {score*100:.3f}")

    vprint("Packet recognition finished successfully.")

def add_to_batch(label, score, src_ip, dst_ip, severity="high"):
    global batch_alerts
    alert_entry = {
        "label": label,
        "score": score,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "severity": severity,
        "time": time.strftime("%H:%M:%S"),
    }
    batch_alerts.append(alert_entry)

def send_batch_summary():

    global batch_alerts
    if not batch_alerts:
        return
    counts = {}
    for entry in batch_alerts:
        key = entry["label"]
        counts[key] = counts.get(key, 0) + 1

    summary_lines = []
    for label, count in counts.items():
        summary_lines.append(f"🔹 {label}: {count} Time")

    description = (
        f"📡 **Batch Alert Summary ({len(batch_alerts)} events)**\n"
        + "\n".join(summary_lines)
    )

    send_discord_embed(
        title="📊 Batch Network Threat Summary",
        description=description,
        color=3447003, 
        BOT_TOKEN=BOT_TOKEN,
        CHANNEL_ID=CHANNEL_ID,
    )

    batch_alerts = []

def batch_scheduler():
    while True:
        time.sleep(BATCH_INTERVAL)
        send_batch_summary()

def alert(label, score, src_ip, dst_ip, severity="high"):

    if severity == "high":
        title = "🚨🔥 **Attack Detected!** 🔥🚨"
        color = 16711680  
    else:
        title = "⚠️🛡️ **Possible Attack Detected!** 🛡️⚠️"
        color = 16776960  


    description = (
        f"🧩 **Type:** {label}\n"
        f"📊 **Score:** {score*100:.2f}%\n"
        f"🌐 **From IP:** `{src_ip}`\n"
        f"🎯 **To IP:** `{dst_ip}`"
    )

    send_discord_embed(title, description, color=color, BOT_TOKEN=BOT_TOKEN, CHANNEL_ID=CHANNEL_ID)
    console_color = Fore.RED if severity == "high" else Fore.YELLOW
    print(console_color + title)
    print(console_color + f"🧩 Type: {label}")
    print(console_color + f"📊 Score: {score*100:.2f}%")
    print(console_color + f"🌐 From IP: {src_ip}")
    print(console_color + f"🎯 To IP: {dst_ip}")
    print(Style.RESET_ALL + "-"*60)


def send_discord_embed(title, description, color=16711680, BOT_TOKEN="", CHANNEL_ID=""):
    global last_sent_time, last_message_id
    current_time = time.time()
    if current_time - last_sent_time < ALERT_COOLDOWN:
        vprint(f"Cooldown active ({ALERT_COOLDOWN}s). Waiting before sending another message.")
        return

    url = f"https://discord.com/api/v10/channels/{CHANNEL_ID}/messages"
    headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    payload = {"embeds":[{"title": title, "description": description, "color": color}]}

    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code in [200, 201]:
            data = response.json()
            last_message_id = data["id"]
            last_sent_time = current_time
            vprint("Discord embed notification sent successfully.")
            threading.Thread(target=delete_last_message_after_cooldown, args=(BOT_TOKEN, CHANNEL_ID)).start()
            
        else:
            print(Fore.RED + f"Failed to send Discord embed: {response.status_code} {response.text}")
    except Exception as e:
        print(Fore.RED + f"Error sending Discord embed: {e}")

def delete_last_message_after_cooldown(BOT_TOKEN="", CHANNEL_ID=""):
    global last_message_id
    time.sleep(ALERT_COOLDOWN)
    if last_message_id is None:
        return
    url = f"https://discord.com/api/v10/channels/{CHANNEL_ID}/messages/{last_message_id}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    try:
        response = requests.delete(url, headers=headers)
        if response.status_code == 204:
            vprint("Discord message deleted successfully.")
            last_message_id = None
        else:
            print(Fore.RED + f"Failed to delete message: {response.status_code} {response.text}")
    except Exception as e:
        print(Fore.RED + f"Error deleting message: {e}")

def analyze_and_notify(labels, scores, src_ip, dst_ip):
    if not isinstance(scores, np.ndarray) or scores.size != len(labels):
        if VERBOSE:
            print(Fore.RED + "[VERBOSE] Invalid scores or labels.")
        return

    try:
        normal_idx = labels.tolist().index("Normal")
        normal_score = scores[normal_idx]
    except ValueError:
        normal_score = 0

    for label, score in zip(labels, scores):
        if label == "Normal":
            continue


        if score > 0.80:
            severity = "high"
        elif score > normal_score:
            severity = "medium"
        else:
            continue

        vprint(f"{severity.capitalize()} severity detected: {label} ({score*100:.2f}%) from {src_ip} to {dst_ip}")
        alert(label, score, src_ip, dst_ip, severity=severity)

        add_to_batch(label, score, src_ip, dst_ip, severity=severity)



def preprocess(packet_hex, use_ip=True):
    packet_bytes = bytes.fromhex(packet_hex)
    if not packet_bytes or len(packet_bytes) < 10:
        raise ValueError("Invalid packet data received.")
    packet = Ether(packet_bytes)
    if packet.firstlayer().name != "Ethernet":
        packet = CookedLinux(packet_bytes)
        if packet.firstlayer().name != "cooked linux":
            raise ValueError(
                f"{packet.firstlayer().name} frame not implemented. Ethernet and Cooked Linux are only supported."
            )

    if "IP" not in packet or "TCP" not in packet:
        raise ValueError("Only TCP/IP packets are supported.")

    src_ip = packet["IP"].src
    dst_ip = packet["IP"].dst
    payload_bytes = bytes(packet["IP"].payload if use_ip else packet["TCP"].payload)
    payload_length = len(payload_bytes)

    final_data = [
        -1,  
        -1,  
        len(packet_bytes),
        -1,  
        packet["TCP"].sport,
        packet["TCP"].dport,
        len(packet["IP"]),
        payload_length,
        packet["IP"].ttl,
        packet["IP"].tos,
        packet["TCP"].dataofs,
        int(packet["TCP"].flags),
        -1,
    ] + [str(byte) for byte in payload_bytes]

    return " ".join(str(s) for s in final_data)

def predict(models, packet_hex):
    final_format = preprocess(packet_hex, use_ip=True)
    tokenizer = models["tokenizer"]
    model_inputs = tokenizer(final_format[:1024], return_tensors="np")
    input_ids = model_inputs.input_ids
    attention_mask = model_inputs.attention_mask
    if input_ids is None or attention_mask is None:
        print("Error: Tokenization failed.")
        return [], []
    net = models["net"]
    output = net.run(None, {"input_ids": input_ids, "attention_mask": attention_mask})
    if output is None or len(output) == 0:
        print("Error: Model returned no output.")
        return [], []
    logits = output[0]
    if logits is None:
        print("Error: Logits is None.")
        return [], []
    scores = softmax(logits[0])
    if scores.size == 0:
        print("Error: Scores array is empty.")
        return [], []
    idx = np.argsort(-scores)
    labels = np.array(LABELS)[idx]
    scores = scores[idx]
    return labels, scores

def real_time_detection(models):
    def packet_callback(packet):
        if IP in packet and TCP in packet:
            packet_bytes = bytes(packet)
            packet_hex = packet_bytes.hex()
            if not packet_bytes:
                if VERBOSE: print(Fore.YELLOW + "[VERBOSE] Empty packet received. Skipping...")
                return
            
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            vprint(f"Captured packet from {src_ip} to {dst_ip}, length: {len(packet_bytes)} bytes")

            labels, scores = predict(models, packet_hex)
            if labels is None or scores is None or len(labels) != len(scores):
                if VERBOSE: print("[VERBOSE] Invalid model output.")
                return [], []

            analyze_and_notify(labels, scores, src_ip, dst_ip)

            top_k = 21
            if VERBOSE:
                vprint("Top predictions for this packet:")
                for label, score in list(zip(labels, scores))[:top_k]:
                    vprint(f"  {label} : {score*100:.3f}") 
                vprint("-" * 100)
    
    ifaces = args.iface
    filter = args.filter
    store = args.store
    if VERBOSE: vprint(f"Starting real-time packet capture on interface: {ifaces}, filter: {filter}, store: {store}")
    try:
        sniff(prn=packet_callback, filter=filter, store=store, iface=ifaces)
    except Exception as e:
        if VERBOSE: print(f"[INF] Error during packet sniffing: {e}")

def main():
    check_and_download_models(WEIGHT_PATH, MODEL_PATH, REMOTE_PATH)

    env_id = args.env_id
    rtd = args.rtd

    if not args.onnx:
        net = ailia.Net(MODEL_PATH, WEIGHT_PATH, env_id=env_id)
    elif rtd:
        if args.onnx:
            import onnxruntime
            net = onnxruntime.InferenceSession(WEIGHT_PATH)
        tokenizer = AutoTokenizer.from_pretrained("tokenizer")
        models = {"tokenizer": tokenizer, "net": net}
        real_time_detection(models)
        return
    else:
        import onnxruntime
        net = onnxruntime.InferenceSession(WEIGHT_PATH)

    tokenizer = AutoTokenizer.from_pretrained("tokenizer")
    models = {"tokenizer": tokenizer, "net": net}

    if args.hex:  
        recognize_from_packet(models)
    else:
        vprint("Starting standard packet recognition...")
        recognize_from_packet(models)

if __name__ == "__main__":
    threading.Thread(target=batch_scheduler, daemon=True).start()
    try:
        main()
    except KeyboardInterrupt:
        print('User interruption')
