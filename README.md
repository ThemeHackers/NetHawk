# 🦅 NetHawk - AI-Driven Network Security & Intrusion Detection System

![NetHawk Dashboard Mockup](https://raw.githubusercontent.com/ThemeHackers/NetHawk/main/assets/banner.png)

NetHawk is a state-of-the-art **AI-IPS (Intrusion Prevention System)** designed for real-time network traffic analysis, threat scoring, and automated defense. Built with a dual-engine architecture, it combines deep packet inspection (DPI) with an **AnomalyGuard** self-learning model to detect both known vulnerabilities and zero-day threats.

---

## 🌟 Key Features

- **🛡️ Multi-Vector Threat Analysis**: Real-time detection of DoS, DDoS, Port Scans, SQL Injections, Botnets, and more across 24+ attack categories.
- **🧠 AnomalyGuard (Zero-Day Detector)**: A specialized neural network that learns your network's normal behavior and flags unknown anomalies that traditional signatures might miss.
- **🤖 AI Security Advisor**: Integrated with **TinyLlama-1.1B**, providing human-readable incident analysis and mitigation strategies directly on your dashboard.
- **🌐 Dual-Stack Support**: Full support for both **IPv4** and **IPv6** traffic analysis.
- **💻 Dynamic Web Dashboard**: A premium, glassmorphism-style web interface (React-inspired) for remote monitoring and deep threat investigation.
- **📊 Terminal TUI**: A beautiful, real-time Terminal User Interface powered by `Rich`, perfect for headless server monitoring.
- **⚡ Hardware Acceleration**: Automatically detects and utilizes **NVIDIA CUDA** for ultra-fast AI inference.
- **🔑 Persistent Configuration**: Seamlessly manages API tokens (HuggingFace) and system settings via `config.ini`.

---

## 🚀 Getting Started

### Prerequisites
- Windows 10/11 or Linux
- **Npcap** (Windows) or **Libpcap** (Linux)
- Python 3.10+
- (Optional) NVIDIA GPU with CUDA for better performance

### Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/ThemeHackers/NetHawk.git
   cd NetHawk
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize Configuration:**
   Create or edit `config.ini` in the root directory:
   ```ini
   [Notifications]
   BOT_TOKEN = YOUR_DISCORD_BOT_TOKEN
   CHANNEL_ID = YOUR_DISCORD_CHANNEL_ID
   ALERT_COOLDOWN = 60

   [Model]
   WEIGHT_PATH = model.onnx
   MODEL_PATH = model.onnx.prototxt
   HF_TOKEN = YOUR_HUGGINGFACE_TOKEN (Optional)

   [Performance]
   BATCH_SIZE = 32
   THROTTLE_DELAY = 0.05
   ```

---

## 🛠️ Usage

### Run NetHawk
Run the main script with Administrator/Root privileges:
```bash
# Auto-detect best interface and start sniffing
python nethawk.py

# Specify interface and BPF filter
python nethawk.py --iface "Ethernet" --filter "tcp port 80" --verbose
```

### Accessing the Dashboard
Once started, the system will launch two interfaces:
1. **Terminal UI**: Real-time stats and packet monitor in your console.
2. **Web Dashboard**: Open `http://127.0.0.1:8000` in your browser for the full visual experience.

---

## 🏷️ Threat Classification Labels
NetHawk classifies traffic into the following 24 categories:
1. **Normal** (Clean Traffic)
2. **DoS / DDoS** (Hulk, GoldenEye, Slowloris, etc.)
3. **Web Attacks** (SQL Injection, XSS, Brute Force)
4. **Network Scans** (Port Scan, Reconnaissance)
5. **Malware Activity** (Botnets, Backdoors, Worms, Shellcode)
6. **Exploits & Fuzzers**

---

## 🔒 Security & Privacy
NetHawk is designed for security professionals and network administrators. Always ensure you have explicit permission to monitor network traffic on your chosen environment.

---

## 🤝 Contributions
Contributions are welcome! Whether it's improving the AI models, adding new protocol support, or enhancing the dashboard UI, feel free to submit a Pull Request.

**Author:** [ThemeHackers](https://github.com/ThemeHackers)  
**License:** MIT License
