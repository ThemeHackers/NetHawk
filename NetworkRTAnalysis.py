import sys
import os
import requests
import json
from colorama import Fore, Style , init
from logging import getLogger
from dotenv import load_dotenv

import numpy as np
from scapy.all import Ether, CookedLinux, sniff, IP, TCP
from transformers import AutoTokenizer
import ailia
import smtplib
from email.mime.text import MIMEText

load_dotenv() 

util_path = "util"
sys.path.append(util_path)

from arg_utils import get_base_parser, update_parser
from model_utils import check_and_download_models
from math_utils import softmax

init(autoreset=True)
logger = getLogger(__name__)

# ======================
# Parameters
# ======================

LINE_NOTIFY_TOKEN = os.getenv("LINE_NOTIFY_TOKEN")
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")
WEIGHT_PATH = "model.onnx"
MODEL_PATH = "model.onnx.prototxt"
REMOTE_PATH = "https://storage.googleapis.com/ailia-models/bert-network-packet-flow-header-payload/"

LABELS = [
    "Analysis", "Backdoor", "Bot", "DDoS", "DoS", "DoS GoldenEye", "DoS Hulk", "DoS SlowHTTPTest", "DoS Slowloris", 
    "Exploits", "FTP Patator", "Fuzzers", "Generic", "Heartbleed", "Infiltration", "Normal", "Port Scan", "Reconnaissance", 
    "SSH Patator", "Shellcode", "Web Attack - Brute Force", "Web Attack - SQL Injection", "Web Attack - XSS", "Worms",
]

PACKEt_HEX_PATH = "input_hex.txt"

# ======================
# Argument Parser Config
# ======================

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
# Additional Functions
# ======================

def send_email(subject, message):
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print(Fore.GREEN + f"Email sent: {subject}")
    except Exception as e:
        print(Fore.GREEN + f"Error sending email: {e}")

def send_line_notify(message):
    url = 'https://notify-api.line.me/api/notify'
    headers = {'Authorization': f'Bearer {LINE_NOTIFY_TOKEN}'}
    payload = {'message': message}
    
    try:
        response = requests.post(url, headers=headers, data=payload)
        if response.status_code == 200:
            print(Fore.GREEN + "Line notify sent successfully")
        else:
            print(Fore.GREEN + "Failed to send Line notify")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def analyze_and_notify(labels, scores, src_ip, dst_ip):
    if isinstance(scores, np.ndarray) and scores.size > 1:
        if not np.all(np.isfinite(scores)):
            print(Fore.RED + "Warning: Scores contain invalid values.")
            return

        normal_idx = labels.tolist().index("Normal")
        normal_score = scores[normal_idx]

        for label, score in zip(labels, scores):
            if score > 0.80:
                if label != "Normal":
            
                    send_line_notify(f"Attack detected! Type: {label} (Score: {score * 100:.3f}) from IP: {src_ip} to IP: {dst_ip}")
                    send_email(f"Attack Detected: {label}", f"Attack Type: {label}, Score: {score * 100:.3f}\nSource IP: {src_ip}\nDestination IP: {dst_ip}")
            elif label != "Normal" and score > scores[normal_idx]:
       
                send_line_notify(f"Possible attack detected! Type: {label} (Score: {score * 100:.3f}) from IP: {src_ip} to IP: {dst_ip}")
                send_email(f"Possible Attack Detected: {label}", f"Possible Attack Type: {label}, Score: {score * 100:.3f}\nSource IP: {src_ip}\nDestination IP: {dst_ip}")

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

def real_time_detection(models):
    def packet_callback(packet):
        if IP in packet and TCP in packet:
            packet_bytes = bytes(packet)
            packet_hex = packet_bytes.hex()

            if not packet_bytes:
                logger.warning("Received an empty packet. Skipping...")
                return

            logger.info(f"Processing packet: {packet_hex[:200]}...")

        
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

            labels, scores = predict(models, packet_hex)

            if labels is None or scores is None or len(labels) != len(scores):
                logger.error("Invalid model output.")
                return [], []

            analyze_and_notify(labels, scores, src_ip, dst_ip)

            top_k = 21
            for label, score in list(zip(labels, scores))[:top_k]:
                print(f"{label} : {score*100:.3f}") 
            print("-" * 100)
    ifaces = args.ifaces
    logger.info("Starting real-time packet capture...")
    try:
        sniff(prn=packet_callback, filter="", store=0, iface=ifaces)
    except Exception as e:
        logger.error(f"Error occurred while sniffing packets: {e}")

def main():
    check_and_download_models(WEIGHT_PATH, MODEL_PATH, REMOTE_PATH)

    env_id = args.env_id
    if not args.onnx:
        net = ailia.Net(MODEL_PATH, WEIGHT_PATH, env_id=env_id)
    else:
        import onnxruntime
        net = onnxruntime.InferenceSession(WEIGHT_PATH)

    if args.disable_ailia_tokenizer:
        tokenizer = AutoTokenizer.from_pretrained("tokenizer")
    else:
        from ailia_tokenizer import BertTokenizer
        tokenizer = BertTokenizer.from_pretrained("./tokenizer/")

    models = {
        "tokenizer": tokenizer,
        "net": net,
    }

    real_time_detection(models)

if __name__ == "__main__":
    main()
