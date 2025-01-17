import sys
import os
import requests
from colorama import Fore, Style, init
from logging import getLogger
import numpy as np
from scapy.all import Ether, CookedLinux, sniff, IP, TCP
from transformers import AutoTokenizer
import ailia
import configparser
import time
import traceback
import onnxruntime

util_path = "util"
sys.path.append(util_path)

from arg_utils import get_base_parser, update_parser
from model_utils import check_and_download_models
from math_utils import softmax


init(autoreset=True)
logger = getLogger(__name__)

# ======================
# Read Configuration
# ======================
config = configparser.ConfigParser()
config.read('config.ini')
LINE_NOTIFY_TOKEN = config['Notifications']['LINE_NOTIFY_TOKEN']
EMAIL_SENDER = config['Email']['EMAIL_SENDER']
EMAIL_PASSWORD = config['Email']['EMAIL_PASSWORD']
EMAIL_RECEIVER = config['Email']['EMAIL_RECEIVER']
WEIGHT_PATH = config['Model']['WEIGHT_PATH']
MODEL_PATH = config['Model']['MODEL_PATH']
REMOTE_PATH = config['Model']['REMOTE_PATH']

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

# ======================
# Argument Parser Config
# ======================

parser = get_base_parser(
    "bert-network-packet-flow-header-payload",
    PACKEt_HEX_PATH,
    None,
)
parser.add_argument("--hex", type=str, default=None, help="Input-HEX data.")
parser.add_argument("--iface", type=str , help="Network Interface eg; wlan0 eth0 enp0s3")
parser.add_argument("--filter", type=str , help="Adjust the scope of packet capture")
parser.add_argument("--store", type=int , default=0 , help="Captured packets are stored in memory (as a list) and returned when the sniffing session is complete.")
parser.add_argument(
    '--disable_ailia_tokenizer',
    action='store_true',
    help='disable ailia tokenizer.'
)
parser.add_argument("--rtd" , action='store_true' , help="Real-time packet detection and network threat analysis using AI")
parser.add_argument("--ip", action="store_true", help="Use IP layer as payload.")
parser.add_argument("--onnx", action="store_true", help="execute onnxruntime version.")
args = update_parser(parser)

# ======================
# Additional Functions
# ======================

def recognize_from_packet(models):
    packet_hex = args.hex
    if packet_hex:
        args.input[0] = packet_hex

   
    for packet_path in args.input:
       
        if os.path.isfile(packet_path):
            logger.info(packet_path)
            with open(packet_path, "r") as f:
                packet_hex = f.read()

       
        logger.info("Start inference...\n")
        if args.benchmark:
            logger.info("BENCHMARK mode")
            total_time_estimation = 0
            for i in range(args.benchmark_count):
                start = int(round(time.time() * 1000))
                output = predict(models, packet_hex)
                end = int(round(time.time() * 1000))
                estimation_time = end - start

                logger.info(f"\tailia processing estimation time {estimation_time} ms")
                if i != 0:
                    total_time_estimation = total_time_estimation + estimation_time

            logger.info(
                f"\taverage time estimation {total_time_estimation / (args.benchmark_count - 1)} ms"
            )
        else:
            output = predict(models, packet_hex)
            
    top_k = 24
    labels, socres = output

    for label, score in list(zip(labels, socres))[:top_k]:
        
        print(f"{label} : {score*100:.3f}")

    logger.info("Script finished successfully...")


def send_line_notify(message):
    url = "https://notify-api.line.me/api/notify"
    headers = {"Authorization": f"Bearer {LINE_NOTIFY_TOKEN}"}
    payload = {"message": message}

    retries = 5  
    for attempt in range(retries):
        try:
            response = requests.post(url, headers=headers, data=payload)
            if response.status_code == 200:
                print(Fore.GREEN + "Notification sent successfully!")
                break  
            else:
                print(Fore.RED + f"Failed to send LINE notification: {response.status_code} {response.text}")
        except Exception as e:
            print(Fore.RED + f"An error occurred while sending LINE notification: {e}")
        
      
        if attempt < retries - 1:
            print(f"Retrying in 5 seconds... ({attempt + 1}/{retries})")
            time.sleep(5)


def send_alert(alert_message):
    send_line_notify(alert_message)

def analyze_and_notify(labels, scores, src_ip, dst_ip):
    if not isinstance(scores, np.ndarray) or scores.size <= 1:
        return
    
    if not np.all(np.isfinite(scores)):
        print(Fore.RED + "Warning: Scores contain invalid values.")
        return
    
    thresholds = {
        "Analysis": 0.70, "Backdoor": 0.90, "Bot": 0.85, "DDoS": 0.90, "DoS": 0.85,
        "DoS GoldenEye": 0.80, "DoS Hulk": 0.80, "DoS SlowHTTPTest": 0.80, "DoS Slowloris": 0.80,
        "Exploits": 0.85, "FTP Patator": 0.75, "Fuzzers": 0.80, "Generic": 0.70, "Heartbleed": 0.90,
        "Infiltration": 0.95, "Normal": 0.60, "Port Scan": 0.75, "Reconnaissance": 0.70,
        "SSH Patator": 0.80, "Shellcode": 0.85, "Web Attack - Brute Force": 0.85, 
        "Web Attack - SQL Injection": 0.90, "Web Attack - XSS": 0.80, "Worms": 0.85,
    }

    normal_idx = labels.tolist().index("Normal")
    normal_score = scores[normal_idx]
    
   
    if normal_score < thresholds["Normal"]:
        alert_message = (
            f"⚠️ Possible system under attack detected!\n"
            f"Normal score dropped below threshold.\n"
            f"Score: {normal_score * 100:.3f}%\n"
            f"From IP: {src_ip}\n"
            f"To IP: {dst_ip}"
        )
        send_alert(alert_message)

    
    for label, score in zip(labels, scores):
        threshold = thresholds.get(label, 0.80)
        
        
        if label == "Normal":
            continue

        
        if score >= threshold:
            alert_message = (
                f"⚠️ System under attack detected!\n"
                f"Type: {label}\n"
                f"Score: {score * 100:.3f}%\n"
                f"From IP: {src_ip}\n"
                f"To IP: {dst_ip}"
            )
            send_alert(alert_message)
        
        
        elif 0.30 <= score < threshold:
            alert_message = (
                f"⚠️ Anomaly detected!\n"
                f"Type: {label}\n"
                f"Score: {score * 100:.3f}%\n"
                f"From IP: {src_ip}\n"
                f"To IP: {dst_ip}"
            )
            send_alert(alert_message)



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

# ===========================
# Display for terminal clear
# ===========================

def display_terminal_clear():
    print(rf'''
{Fore.CYAN}{Style.BRIGHT}  
            _   _      _   _    _                _    
           | \ | |    | | | |  | |              | |   
           |  \| | ___| |_| |__| | __ ___      _| | __
           | . ` |/ _ \ __|  __  |/ _` \ \ /\ / / |/ / 
           | |\  |  __/ |_| |  | | (_| |\ V  V /|   <  
           |_| \_|\___|\__|_|  |_|\__,_| \_/\_/ |_|\_\
{Style.RESET_ALL}
        {Fore.GREEN}Author: ThemeHackers
        {Fore.GREEN}Github: https://github.com/ThemeHackers/NetHawk.git
        {Fore.GREEN}NetHawk is your network security analysis tool with many features and alerts when network attacks occur with score report and attack path shown as IP.    
{Style.RESET_ALL}
''')

# ======================
# Real time detection
# ======================

def real_time_detection(models):
    def packet_callback(packet):
        
        if IP in packet and TCP in packet:
            packet_bytes = bytes(packet)
            packet_hex = packet_bytes.hex()

            if not packet_bytes:
                logger.warning("Received an empty packet. Skipping...")
                return
            logger.info(Fore.RED + f"Processing packet: {packet_hex[:125]}...")

            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

            labels, scores = predict(models, packet_hex)
            if labels is None or scores is None or len(labels) != len(scores):
                logger.error("Invalid model output.")
                return [], []

            analyze_and_notify(labels, scores, src_ip, dst_ip)
    
            os.system("clear")
            display_terminal_clear()
            top_k = 24

            for label, score in list(zip(labels, scores))[:top_k]:
                print(f"{label} : {score*100:.3f}%")
    
            print("-" * 150)        

    ifaces = args.iface
    filter = args.filter
    store = args.store
    logger.info("Starting real-time packet capture...")

    while True:
        try:
            sniff(prn=packet_callback, filter=filter, store=store, iface=ifaces)
        except Exception as e:
            logger.error(f"Error occurred while sniffing packets: {repr(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            logger.info("Network error detected. Retrying in 10 seconds...")
            time.sleep(10) 

# ======================
# Main function
# ======================

def main():
    check_and_download_models(WEIGHT_PATH, MODEL_PATH, REMOTE_PATH)
    
    env_id = args.env_id
    rtd = args.rtd

    if not args.onnx:
        net = ailia.Net(MODEL_PATH, WEIGHT_PATH, env_id=env_id)
    elif rtd:
       
        if args.onnx:
           
            net = onnxruntime.InferenceSession(WEIGHT_PATH)

        tokenizer = AutoTokenizer.from_pretrained("tokenizer")

        models = {
            "tokenizer": tokenizer,
            "net": net,
        }

        real_time_detection(models)
        return

    else:
     
        net = onnxruntime.InferenceSession(WEIGHT_PATH)

    tokenizer = AutoTokenizer.from_pretrained("tokenizer")

    models = {
        "tokenizer": tokenizer,
        "net": net,
    }

    if args.hex:  
        recognize_from_packet(models)
    else:
        logger.info("Starting standard packet recognition...")
        
        recognize_from_packet(models)


if __name__ == "__main__":
    main()
