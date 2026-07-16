# 🛡️ Network Intrusion Detection System (IDS)

Real-time network monitoring with **MITRE ATT&CK mapping**, **host reputation**, and **live threat intelligence**.

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com)
[![SocketIO](https://img.shields.io/badge/SocketIO-5.9-orange.svg)](https://socket.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ✨ Features

### 🔥 Detection Engine
- 12+ attack types (Neptune, Portsweep, Ipsweep, Smurf, Satan, Back, Teardrop, Warezclient, Guess_Passwd, Mscan, Processtable, Pod)
- NSL-KDD feature extraction (40+ features per flow)
- Scored matching with configurable confidence thresholds
- TCP state machine tracking (SF, S0, REJ, RSTO, etc.)
- Cross-flow aggregation for accurate detection
- Host reputation scoring per source IP

### 📊 SOC Dashboard
- Live packet capture with real-time analysis
- 6+ interactive charts (traffic, attacks, protocols, timeline, top sources, services)
- Searchable, sortable, filterable flow table
- Flow inspector with MITRE ATT&CK mapping
- Alert management with investigation workflow
- System health monitoring (CPU, Memory, Queue, Uptime)
- Dark SOC theme optimized for monitoring

### 🛡️ Security Intelligence
- MITRE ATT&CK technique mapping (T1046, T1498, T1110, etc.)
- Host reputation scoring per source IP
- IOC detection (IPs, CIDRs, domains)
- Reverse DNS enrichment
- Alert acknowledgment and false positive flagging

### 🚀 Performance
- Async event-driven architecture
- Packet sampling for high throughput
- SQLite persistence for alerts and flows
- Real-time WebSocket updates
- Throttled UI updates for smooth performance

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Flask, Flask-SocketIO, eventlet |
| Packet Capture | pyshark (tshark wrapper) |
| System Monitoring | psutil |
| Frontend | Vanilla JS (ES6 modules), Chart.js |
| Database | SQLite |
| Styling | CSS3 with CSS variables |
| Real-time | WebSocket (Socket.IO) |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- tshark (Wireshark CLI)

**Install tshark:**
```bash
# Ubuntu/Debian
sudo apt-get install tshark

# macOS
brew install wireshark

# Windows
# Download from https://www.wireshark.org/download.html
# Make sure tshark.exe is on PATH
