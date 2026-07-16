# 🛡️ Network Intrusion Detection System (IDS)

Real-time network monitoring with **MITRE ATT&CK mapping**, **host reputation**, and **live threat intelligence**.

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com)
[![SocketIO](https://img.shields.io/badge/SocketIO-5.9-orange.svg)](https://socket.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Detection Engine](#-detection-engine)
- [MITRE ATT&CK Mappings](#-mitre-attck-mappings)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [License](#-license)

---

## ✨ Features

### 🔥 Detection Engine
- **12+ attack types**: Neptune, Portsweep, Ipsweep, Smurf, Satan, Back, Teardrop, Warezclient, Guess_Passwd, Mscan, Processtable, Pod
- **NSL-KDD feature extraction**: 40+ features per flow
- **Scored matching** with configurable confidence thresholds (0.5 - 1.0)
- **TCP state machine tracking** (SF, S0, REJ, RSTO, etc.)
- **Cross-flow aggregation** for accurate detection
- **Host reputation scoring** per source IP

### 📊 SOC Dashboard
- Live packet capture with real-time analysis
- 6+ interactive charts (traffic, attacks, protocols, timeline, top sources, services)
- Searchable, sortable, filterable flow table
- Flow inspector with MITRE ATT&CK mapping
- Alert management with investigation workflow
- System health monitoring (CPU, Memory, Queue, Uptime)
- Dark SOC theme optimized for monitoring

### 🛡️ Security Intelligence
- **MITRE ATT&CK technique mapping** (T1046, T1498, T1110, etc.)
- **Host reputation** scoring per source IP
- **IOC detection** (IPs, CIDRs, domains)
- **Reverse DNS** enrichment
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
| **Backend** | Flask, Flask-SocketIO, eventlet |
| **Packet Capture** | pyshark (tshark wrapper) |
| **System Monitoring** | psutil |
| **Frontend** | Vanilla JS (ES6 modules), Chart.js |
| **Database** | SQLite |
| **Styling** | CSS3 with CSS variables |
| **Real-time** | WebSocket (Socket.IO) |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- tshark (Wireshark CLI)

**Install tshark:**
```
# Ubuntu/Debian
sudo apt-get install tshark

# macOS
brew install wireshark

# Windows
# Download from https://www.wireshark.org/download.html
# Make sure tshark.exe is on PATH
```

### Installation

```
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/ids-dashboard.git
cd ids-dashboard

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate      # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Update config.json with your network interface
tshark -D  # List available interfaces
# Edit config.json and set "interface" to your interface name

# 5. Run the application
python app.py

# 6. Open browser
http://localhost:5000
```

---

## 🔧 Detection Engine

### What Was Broken & How We Fixed It

The original detection engine had three critical bugs that rendered it ineffective:

#### 1. TCP Flag Detection
**Problem:** The `flag` feature was computed from a single packet's raw TCP-flags byte. An ordinary PSH+ACK data packet matched the table entry for `RSTO`, causing routine traffic to satisfy attack signatures by accident.

**Fix:** Implemented `ConnState` class that tracks the SYN / SYN-ACK / ACK / FIN / RST sequence across the **whole connection**, matching the actual Zeek/Bro `conn_state` values.

#### 2. Cross-Flow Features
**Problem:** `dst_host_count` and all `dst_host_*` features were computed from a single flow's own packet history. A single 5-tuple connection only has one destination IP, so `dst_host_count` was stuck at 1 forever, meaning `satan`, `smurf`, and `portsweep` could never fire.

**Fix:** Implemented `HostConnectionTracker` that tracks:
- 2-second time window across ALL connections (for `count`, `srv_count`, `*error_rate`)
- 100-connection window per destination host (for `dst_host_*` features)

#### 3. Matching Logic
**Problem:** Matching required **every single** zero_field and range condition to hold simultaneously (strict AND across 15-38 conditions). Real traffic has jitter.

**Fix:** Scored matching – `zero_fields` and `ranges` contribute to a score (fraction satisfied) rather than being all-or-nothing.

### Detection Architecture

```
Network Packet
      ↓
pyshark Capture
      ↓
ConnState (TCP state tracking)
      ↓
HostConnectionTracker (cross-flow aggregation)
      ↓
FlowFeatures (40+ NSL-KDD features)
      ↓
score_attack() (scored matching)
      ↓
classify() (pick highest scoring attack above threshold)
      ↓
Alert → Dashboard → Socket.IO → Frontend
```

---

## 🎯 MITRE ATT&CK Mappings

| Attack | MITRE Techniques | Tactic |
|--------|------------------|--------|
| Neptune (SYN Flood) | T1498, T1499 | Impact |
| Portsweep | T1046 | Discovery |
| Ipsweep | T1046 | Discovery |
| Smurf (ICMP Flood) | T1498, T1499 | Impact |
| Satan | T1046, T1595 | Reconnaissance |
| Back | T1046, T1190 | Initial Access |
| Teardrop | T1498 | Impact |
| Warezclient | T1048 | Exfiltration |
| Guess_Passwd | T1110 | Credential Access |
| Mscan | T1046, T1595 | Reconnaissance |
| Processtable | T1005 | Impact |
| Pod (Ping of Death) | T1498 | Impact |

---

## 📁 Project Structure

```
ids-dashboard/
├── app.py                 # Flask backend + detection engine
├── config.json            # Configuration
├── requirements.txt       # Python dependencies
├── README.md              # Documentation
├── LICENSE                # MIT License
├── .gitignore             # Git ignore rules
│
├── templates/
│   ├── base.html          # Base template (sidebar, navigation)
│   ├── index.html         # Dashboard page
│   ├── alerts.html        # Alerts page
│   ├── flows.html         # Flows page
│   ├── export.html        # Export page
│   └── settings.html      # Settings page
│
├── static/
│   ├── css/
│   │   └── style.css      # All styles (dark SOC theme)
│   └── js/
│       ├── app.js         # Entry point (orchestrator)
│       ├── socket.js      # Socket.IO communication
│       ├── dashboard.js   # State management
│       ├── table.js       # Table rendering
│       ├── charts.js      # Chart.js visualizations
│       ├── alerts.js      # Alert management
│       ├── inspector.js   # Flow inspector (MITRE mapping)
│       ├── filters.js     # Search & filters
│       ├── exporter.js    # Export (CSV, JSON, PCAP)
│       ├── settings.js    # Settings UI
│       └── utils.js       # Helper functions
│
├── data/                  # Runtime (auto-created)
│   ├── alerts.db          # Alerts database
│   └── flows.db           # Flows database
│
└── test_pcaps/            # (Optional) Test PCAP files
```

---

## ⚙️ Configuration

### `config.json`

| Key | Description | Default |
|-----|-------------|---------|
| `interface` | Network interface to capture on | `"eth0"` |
| `match_threshold` | Detection confidence threshold (0.5-1.0) | `0.95` |
| `half_open_grace_seconds` | Wait time before classifying half-open connections | `2.0` |
| `half_open_min_count` | Minimum half-open connections to trigger detection | `10` |
| `sampling_rate` | Process 1 of N packets (higher = less CPU) | `1` |
| `capture_bpf` | BPF filter (e.g., `"tcp port 80"`) | `null` |
| `portsweep_port_threshold` | Number of ports to trigger portsweep | `10` |
| `ipsweep_host_threshold` | Number of hosts to trigger ipsweep | `10` |

### Tuning Recommendations

| Scenario | Match Threshold | Grace Period | Sampling Rate |
|----------|-----------------|--------------|---------------|
| **Low false positives** | 0.95 | 2.0s | 1 |
| **Balanced** | 0.90 | 1.0s | 2 |
| **High detection** | 0.80 | 0.5s | 1 |
| **High traffic load** | 0.90 | 1.0s | 5-10 |

---

## 🧪 Testing Without Live Capture

```
# Run offline detection test harness
python test_detection.py
```

Expected results:
- Normal traffic → `normal`
- SYN flood → `neptune`
- Port scan → `portsweep`
- Host scan → `ipsweep`
- ICMP flood → `smurf` or `ipsweep`

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html) for attack signatures
- [MITRE ATT&CK](https://attack.mitre.org/) for threat intelligence mapping
- [Chart.js](https://www.chartjs.org/) for visualizations
- [pyshark](https://github.com/KimiNewt/pyshark) for packet capture

---

## 👨‍💻 Author

**Your Name**
- GitHub: [@YOUR_USERNAME](https://github.com/YOUR_USERNAME)
- LinkedIn: [Your LinkedIn](https://linkedin.com/in/YOUR_LINKEDIN)

---

## ⭐ Support

If you find this project useful, please give it a star on GitHub!

---

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **No packets captured** | Check `config.json` interface name: `tshark -D` |
| **Permission denied** | Run with `sudo` on Linux, Administrator on Windows |
| **Port 5000 already in use** | Change port in `app.py`: `socketio.run(app, debug=False, port=5001)` |
| **Socket.IO not connecting** | Check CORS settings in `app.py` |
| **CPU alternating 0** | Fixed in `get_system_health()` with cached CPU values |

### Debug Mode

Add to `app.py` to enable debug logging:

```python
logging.basicConfig(level=logging.DEBUG)
```

---

## 🚀 Roadmap

- [ ] Network graph visualization
- [ ] PDF report generation
- [ ] Email/Slack alerts
- [ ] Attack story timeline
- [ ] Multi-user support

---

**Built with ❤️ for security monitoring**
