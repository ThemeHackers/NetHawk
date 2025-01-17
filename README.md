# NetHawk - Network Security Analysis Tool - Linux 

## Description

NetHawk is a powerful network security analysis tool designed to detect and analyze various network threats, including DoS attacks, DDoS attacks, port scans, SQL injections, backdoor attempts, and more. The tool leverages machine learning models to analyze network traffic in real-time, identify anomalies, and send alerts if suspicious behavior is detected. It supports a variety of attacks and can be configured to suit different network environments. The tool uses packet capture techniques and can process both pre-captured packet data and real-time network traffic.

## Features

- **Real-Time Packet Detection**: Captures and processes network packets in real-time, analyzing traffic for potential threats and generating alerts.
- **AI-based Threat Detection**: Utilizes pre-trained machine learning models to classify and score various types of network threats.
- **Packet Analysis**: The tool decodes packet data and uses the IP and TCP layers to identify attack types.
- **Customizable Alerting**: Configurable thresholds to send notifications via LINE or email if certain attack thresholds are exceeded.
- **Configurable Network Interface**: Users can specify the network interface (e.g., `wlan0`, `eth0`) for packet sniffing.
- **Support for Pre-Captured Packet Data**: Allows processing of network packet data provided as hex dumps.
- **Model Inference via ONNX Runtime**: Supports ONNX-based model inference for flexible deployment.

## config.ini

The `config.ini` file is used to store necessary configuration settings. Below is the format for the configuration file:

```ini
[Notifications]
LINE_NOTIFY_TOKEN = your_line_notify_token_here

[Email]
EMAIL_SENDER = sender_email_here
EMAIL_PASSWORD = sender_email_password_here
EMAIL_RECEIVER = receiver_email_here

[Model]
WEIGHT_PATH = model.onnx
MODEL_PATH = model.onnx.prototxt
REMOTE_PATH = https://storage.googleapis.com/ailia-models/bert-network-packet-flow-header-payload/
```
## Labels
The system classifies threats into the following categories:

1. **Analysis**
2. **Backdoor**
3. **Bot**
4. **DDoS**
5. **DoS**
6. **DoS GoldenEye**
7. **DoS Hulk**
8. **DoS SlowHTTPTest**
9. **DoS Slowloris**
10. **Exploits**
11. **FTP Patator**
12. **Fuzzers**
13. **Generic**
14. **Heartbleed**
15. **Infiltration**
16. **Normal**
17. **Port Scan**
18. **Reconnaissance**
19. **SSH Patator**
20. **Shellcode**
21. **Web Attack - Brute Force**
22. **Web Attack - SQL Injection**
23. **Web Attack - XSS**
24. **Worms**

## Usage

### Command-Line Arguments

| Argument                     | Description                                           |
|------------------------------|-------------------------------------------------------|
| `--hex`                      | Input HEX data for offline packet analysis.          |
| `--iface`                    | Network interface for real-time detection (e.g., eth0, wlan0). |
| `--filter`                   | Berkeley Packet Filter (BPF) string to filter packets. |
| `--store`                    | Store captured packets in memory (default: 0).       |
| `--rtd`                      | Enable real-time detection.                          |
| `--ip`                       | Use IP layer as payload (default: True).             |
| `--onnx`                     | Use ONNX runtime for inference.                      |
| `--disable_ailia_tokenizer`  | Disable Ailia tokenizer.                             |

### Examples

#### Real-Time Detection
```bash
python nethawk.py --rtd --iface eth0 --filter "tcp" --ip --onnx
```

#### HEX Packet Analysis
```bash
python nethawk.py --hex <packet_hex_data> --onnx
```

## Contributions
Contributions are welcome! Feel free to fork the repository and submit a pull request with your improvements.

