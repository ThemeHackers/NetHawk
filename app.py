import os
import requests
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP
from transformers import AutoTokenizer
import numpy as np
import ailia
from math_utils import softmax
from dotenv import load_dotenv
from logging import getLogger

util_path = "util"
sys.path.append(util_path)

from arg_utils import get_base_parser, update_parser
from model_utils import check_and_download_models
from math_utils import softmax

load_dotenv()

app = Flask(__name__)
socketio = SocketIO(app)
logger = getLogger(__name__)
# ======================
# Parameters
# ======================
LINE_NOTIFY_TOKEN = os.getenv("LINE_NOTIFY_TOKEN")
WEIGHT_PATH = "model.onnx"
MODEL_PATH = "model.onnx.prototxt"
LABELS = [
    "Analysis", "Backdoor", "Bot", "DDoS", "DoS", "DoS GoldenEye", "DoS Hulk", "DoS SlowHTTPTest", "DoS Slowloris", 
    "Exploits", "FTP Patator", "Fuzzers", "Generic", "Heartbleed", "Infiltration", "Normal", "Port Scan", "Reconnaissance", 
    "SSH Patator", "Shellcode", "Web Attack - Brute Force", "Web Attack - SQL Injection", "Web Attack - XSS", "Worms",
]

# ======================
# Argument Parser Config
# ======================

PACKEt_HEX_PATH = "input_hex.txt"
parser = get_base_parser(
    "bert-network-packet-flow-header-payload",
    PACKEt_HEX_PATH,
    None,
)
parser.add_argument("--hex", type=str, default=None, help="Input-HEX data.")
parser.add_argument("--ip", action="store_true", help="Use IP layer as payload.")
parser.add_argument("--onnx", action="store_true", help="execute onnxruntime version.")
parser.add_argument("--ifaces", help="Network Interface eg; wlan0 eth0 enp0s3")
parser.add_argument(
    '--disable_ailia_tokenizer',
    action='store_true',
    help='disable ailia tokenizer.'
)
args = update_parser(parser)
# ======================
# Model Setup
# ======================

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

    forward_packets = 0
    backward_packets = 0
    bytes_transfered = len(packet_bytes)

    src_ip = packet["IP"].src
    dst_ip = packet["IP"].dst
    ip_length = len(packet["IP"])
    ip_ttl = packet["IP"].ttl
    ip_tos = packet["IP"].tos
    src_port = packet["TCP"].sport
    dst_port = packet["TCP"].dport
    tcp_data_offset = packet["TCP"].dataofs
    tcp_flags = packet["TCP"].flags

    payload_bytes = bytes(packet["IP"].payload if use_ip else packet["TCP"].payload)
    payload_length = len(payload_bytes)
    payload_decimal = [str(byte) for byte in payload_bytes]

    final_data = [
        forward_packets,
        backward_packets,
        bytes_transfered,
        -1,
        src_port,
        dst_port,
        ip_length,
        payload_length,
        ip_ttl,
        ip_tos,
        tcp_data_offset,
        int(tcp_flags),
        -1,
    ] + payload_decimal

    final_data = " ".join(str(s) for s in final_data)
    return final_data

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


# ======================
# Real-time Packet Detection
# ======================

def packet_callback(packet):
    if IP in packet and TCP in packet:
        packet_bytes = bytes(packet)
        packet_hex = packet_bytes.hex()

        if not packet_bytes:
            print("Received an empty packet. Skipping...")
            return

        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst

        labels, scores = predict(models, packet_hex)

        if labels is None or scores is None or len(labels) != len(scores):
            print("Invalid model output.")
            return

        analyze_and_notify(labels, scores, src_ip, dst_ip)

        top_k = 21
        message = f"Source IP: {src_ip}, Destination IP: {dst_ip}\n"
        for label, score in zip(labels[:top_k], scores[:top_k]):
            message += f"{label}: {score * 100:.3f}%\n"

        emit('new_packet', {'message': message})
ifaces = args.iface
def start_packet_capture():
    ifaces = args.iface  
    sniff(prn=packet_callback, filter="", store=0, iface=ifaces)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print("Client connected")
    socketio.emit('status', {'message': 'Connected to WebSocket'})

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected")

if __name__ == "__main__":
    models = {"tokenizer": AutoTokenizer.from_pretrained("bert-base-uncased"),
              "net": ailia.Net(MODEL_PATH, WEIGHT_PATH)}

    
    socketio.start_background_task(start_packet_capture)

    socketio.run(app, host="0.0.0.0", port=5000)
