# NETWORK SNIFFER USING PYTHON (SCAPY)

An advanced Python-based network packet sniffer developed as part of the CodeAlpha Cyber Security Internship.

This project captures and analyzes live network traffic packets in real time, providing detailed insights into network communication, protocols, applications, and traffic behavior.

---

## 🚀 Features

### 📡 Live Packet Capture
- Captures real-time network packets
- Monitors incoming and outgoing traffic

### 🌐 Network Analysis
- Displays source and destination IP addresses
- Resolves hostnames/domains
- Detects protocols such as:
  - TCP
  - UDP
  - ICMP

### 🖥 Application Detection
- Identifies common applications/services using port numbers
- Detects:
  - HTTPS
  - DNS
  - SSH
  - FTP
  - SMTP
  - HTTP
  - and more

### 📊 Traffic Insights
- Total packets captured
- Protocol statistics
- Most contacted destination IPs
- Most used applications/services

### ⚠ Basic Threat Indicators
- Detects unusually large packets
- Warns about unknown application traffic

### 📝 Logging
- Stores captured packet summaries in a log file

---

## 🛠 Technologies Used

- Python
- Scapy
- Socket Programming
- Npcap (Windows packet capture driver)

---

## 📂 Project Structure

```plaintext
CodeAlpha_BasicNetworkSniffer/
│
├── sniffer.py
├── requirements.txt
├── README.md
├── captured_packets.txt
├── .gitignore
│
├── screenshots/
│   ├── output1.png
│   ├── output2.png
│
└── assets/
    └── banner.png
```

---

## ⚡ Installation

### 1. Clone Repository

```bash
git clone YOUR_REPOSITORY_LINK
```

### 2. Move Into Project Directory

```bash
cd CodeAlpha_BasicNetworkSniffer
```

### 3. Create Virtual Environment

```bash
python -m venv venv
```

### 4. Activate Virtual Environment

#### Windows

```bash
venv\Scripts\activate
```

#### Linux/Mac

```bash
source venv/bin/activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🖥 Npcap Installation (IMPORTANT)

This project requires Npcap for packet sniffing on Windows.

Download:

https://npcap.com/#download

During installation:
- Enable WinPcap API-compatible Mode

---

## ▶ Usage

Run the sniffer with administrator/root privileges:

```bash
python sniffer.py
```

---

## 📊 Example Insights

```plaintext
================ NETWORK INSIGHTS ================

Total Packets Captured : 40
TCP Packets            : 25
UDP Packets            : 12
ICMP Packets           : 3

Top Destination IPs:
142.250.183.14 -> 15 packets

Most Used Applications:
HTTPS -> 22 packets
DNS -> 10 packets
```

---

## 📸 Screenshots

### Live Packet Capture

![Output](screenshots/output1.png)

### Network Insights

![Insights](screenshots/output2.png)

---

## ⚠ Disclaimer

This project is intended strictly for educational and ethical purposes only.

Unauthorized packet sniffing or monitoring on networks without proper permission may violate laws and regulations.

---

## 🎯 Learning Outcomes

Through this project, the following cybersecurity concepts were explored:

- Packet sniffing
- Network traffic analysis
- Protocol inspection
- Application/service identification
- Traffic monitoring
- Basic anomaly detection
- Cybersecurity monitoring concepts

---

## 👨‍💻 Author

Akshit Jain

Cyber Security Intern at CodeAlpha