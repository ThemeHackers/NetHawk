# NetHawk - Network Security Analysis Tool 

# What do you work on?

- Ubuntu
- Kali Linux
- ParrotOS

In the future, I will release a supported system on Windows.

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
## Install requirements.txt
  ```bash
  sudo su
  python3 -m venv .venv
  source .venv/bin/activate
  pip3 install -r requirements.txt
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
sudo python nethawk.py --rtd --iface eth0 --filter "tcp" --ip --onnx
```

#### HEX Packet Analysis
```bash
sudo python nethawk.py --hex <packet_hex_data> --onnx
```
## Run services on Linux
- Access the /etc/systemd/system directory file
  ```bash
  cd /etc/systemd/system
  ```
- Access root privileges
  ```bash
  sudo su
  ```
- Create nethawk.service file and edit file
  ```bash
  mkdir nethawk.service
  ```
  ```bash
  [Unit]
  Description=NetHawk - Service is Artificial intelligence systems that detect network threats
  After=network.target

  [Service]
  Type=simple
  Environment="$OPTIONS=OPTIONS"
  ExecStart=/home/user/NetHawk/.venv/bin/python3 /home/user/NetHawk/nethawk.py $OPTIONS
  WorkingDirectory=/home/user/NetHawk
  User=root
  Group=root
  Restart=always
  RestartSec=3

  [Install]
  WantedBy=multi-user.target
  ```
- reload the systemd daemon's configuration
  ```bash
  systemctl daemon-reload
  ```
- Set-Environment OPTIONS , Run service , checking service
  ```bash
  systemctl set-environment OPTIONS="--rtd --iface wlan0 --filter ip --env_id 1 --ip --onnx"
  ```
  
  ```bash
  systemctl start nethawk.service
  ```
  ```bash
  systemctl status nethawk.service
  ```
- Your options can be viewed by running
  ```bash
  python3 nethawk.py -h
  ```
  ```bash
  usage: nethawk.py [-h] [-i [IMAGE/VIDEO ...]] [-v VIDEO] [-s SAVE_PATH] [-b] [-e ENV_ID] [--env_list] [--ftype FILE_TYPE] [--debug] [--profile] [-bc BENCHMARK_COUNT] [--hex HEX] [--    iface IFACE]
                    [--filter FILTER] [--store STORE] [--disable_ailia_tokenizer] [--rtd] [--ip] [--onnx]

  bert-network-packet-flow-header-payload

  options:
    -h, --help            show this help message and exit
    -i [IMAGE/VIDEO ...], --input [IMAGE/VIDEO ...]
                          The default (model-dependent) input data (image / video) path. If a directory name is specified, the model will be run for the files inside. File type is specified by --ftype
                          argument (default: input_hex.txt)
    -v VIDEO, --video VIDEO
                          You can convert the input video by entering style image.If the int variable is given, corresponding webcam input will be used. (default: None)
    -s SAVE_PATH, --savepath SAVE_PATH
                          Save path for the output (image / video / text). (default: None)
    -b, --benchmark       Running the inference on the same input 5 times to measure execution performance. (Cannot be used in video mode) (default: False)
    -e ENV_ID, --env_id ENV_ID
                          A specific environment id can be specified. By default, the return value of ailia.get_gpu_environment_id will be used (default: -1)
    --env_list            display environment list (default: False)
    --ftype FILE_TYPE     file type list: image | video | audio (default: image)
    --debug               set default logger level to DEBUG (enable to show DEBUG logs) (default: False)
    --profile             set profile mode (enable to show PROFILE logs) (default: False)
    -bc BENCHMARK_COUNT, --benchmark_count BENCHMARK_COUNT
                          set iteration count of benchmark (default: 5)
    --hex HEX             Input-HEX data. (default: None)
    --iface IFACE         Network Interface eg; wlan0 eth0 enp0s3 (default: None)
    --filter FILTER       Adjust the scope of packet capture (default: None)
    --store STORE         Captured packets are stored in memory (as a list) and returned when the sniffing session is complete. (default: 0)
    --disable_ailia_tokenizer
                          disable ailia tokenizer. (default: False)
    --rtd                 Real-time packet detection and network threat analysis using AI (default: False)
    --ip                  Use IP layer as payload. (default: False)
    --onnx                execute onnxruntime version. (default: False)

    ```
## More
- real-time log monitoring of systemd
  ```bash
  sudo journalctl -f
  ```
- Filter by importance level
  ```bash
  sudo journalctl -f -p err
  ```
## Contributions
Contributions are welcome! Feel free to fork the repository and submit a pull request with your improvements.

