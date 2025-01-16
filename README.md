# Network Threat Detection using AI

## Overview
This project implements a network threat detection system that leverages AI-based models to analyze network packets in real time or from hexadecimal data. It identifies and classifies various types of cyber threats such as DDoS, port scans, brute force attacks, and more, providing alerts and notifications for detected threats.

## Features

- **Real-time Packet Detection**: Captures and analyzes network traffic in real time.
- **Threat Classification**: Identifies 24 types of cyber threats.
- **AI Integration**: Uses a tokenizer and pre-trained model for inference.
- **Alert Notifications**: Sends LINE notifications when threats are detected.
- **Extensibility**: Modular design allows for the integration of additional models or threat categories.

## Prerequisites

- Python 3.8+
- Required Python Libraries:
  - `sys`, `os`, `requests`, `json`, `configparser`, `time`
  - `numpy`
  - `scapy`
  - `transformers`
  - `ailia`
  - `colorama`
- Network Interface Card (NIC) for real-time detection
- Configuration file (`config.ini`) with appropriate settings.

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

## Configuration

The `config.ini` file should include the following sections:

```ini
[Notifications]
LINE_NOTIFY_TOKEN = <Your LINE Notify Token>

[Email]
EMAIL_SENDER = <Your Email Address>
EMAIL_PASSWORD = <Your Email Password>
EMAIL_RECEIVER = <Recipient Email Address>

[Model]
WEIGHT_PATH = <Path to Model Weights>
MODEL_PATH = <Path to Model Definition>
REMOTE_PATH = <Remote Path to Download Models>
```

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

## Key Functions

### `recognize_from_packet(models)`
Analyzes network packets from hexadecimal data and performs threat classification.

### `real_time_detection(models)`
Captures packets from the specified network interface in real time, analyzes them, and provides threat alerts.

### `preprocess(packet_hex, use_ip=True)`
Processes raw packet data into a format suitable for AI model inference.

### `predict(models, packet_hex)`
Performs inference using the tokenizer and model to classify threats.

### `analyze_and_notify(labels, scores, src_ip, dst_ip)`
Evaluates model predictions and sends LINE notifications for detected threats.

### `send_line_notify(message)`
Sends notifications to the configured LINE account.

## Extending the System

- **Adding New Threat Categories**: Update the `LABELS` list and retrain the model if necessary.
- **Integrating New Models**: Replace the current model with an updated one in the `config.ini` file and adapt the preprocessing pipeline as needed.

## Limitations

- Supports only TCP/IP packets.
- Requires proper configuration of NIC and filtering rules for real-time detection.
- Limited to threats predefined in the `LABELS` list.

## License
This project is released under the MIT License.

## Contributions
Contributions are welcome! Feel free to fork the repository and submit a pull request with your improvements.

