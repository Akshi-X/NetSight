# ⬡ NetSight — AI-Powered Packet Analyzer

NetSight is a modern network packet analysis dashboard with live capture, richer packet inspection, multi-rule anomaly detection, suspicious IP tracking, Gemini AI summaries, incident reporting, and JSON exports.

---

## 🔥 What’s New in This Upgrade

- Complete backend upgrade in `backend/main.py`
- Rich packet parsing for TTL, TCP flags, TCP seq/ack, ICMP type/code, DNS query, ARP op, and safe HTTP header inspection
- 6 anomaly detection rules: High traffic, Port scan, SYN scan, ICMP flood, DNS flood, Burst traffic
- Persistent `alert_history` plus latest `current_alerts`
- Suspicious IP tracker with severity, reasons, packet count, unique ports, protocol set, first/last seen
- Gemini AI integration via `GEMINI_API_KEY` and `google-generativeai`
- 7 new API endpoints for dashboard, suspicious IPs, alert history, report, and exports
- Fully upgraded frontend with dashboard cards, tabbed side panel, protocol filters, suspicious IP panel, export buttons, and detailed packet inspector

---

## 🏗️ Project Structure

```
NetSight/
├── backend/
│   ├── main.py              ← FastAPI backend with Scapy + Gemini AI
│   └── requirements.txt     ← Python dependencies
├── frontend/
│   └── index.html           ← Single-page UI
├── start.sh                 ← Quick-start launcher
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🚀 Run from Scratch

### Recommended setup (venv)

```bash
cd /home/akshi/Downloads/network-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### Start the app

```bash
cd /home/akshi/Downloads/network-analyzer
./start.sh
```

### Live capture mode

For real packet capture, run with sudo:

```bash
sudo python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Open the UI

```text
http://localhost:8000
```

---

## 🌐 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/start` | Start packet capture |
| `POST` | `/stop` | Stop packet capture |
| `GET` | `/packets?since=N` | Get packets after packet id N |
| `GET` | `/packet/{id}` | Get full packet detail |
| `GET` | `/alerts` | Get latest alerts for current cycle |
| `GET` | `/alert-history` | Get full persistent alert history |
| `GET` | `/dashboard` | Get live dashboard stats |
| `GET` | `/suspicious-ips` | Get suspicious IP tracker data |
| `POST` | `/summarize` | Generate traffic summary (`mode=concise` or `mode=detailed`) |
| `POST` | `/report` | Generate incident/security report |
| `GET` | `/status` | Get capture and service status |
| `GET` | `/export/packets` | Export captured packets as JSON |
| `GET` | `/export/alerts` | Export alert history as JSON |
| `GET` | `/export/suspicious-ips` | Export suspicious IPs as JSON |
| `POST` | `/export/report` | Export incident report as text |

---

## 🤖 Gemini AI Integration

NetSight uses Google Gemini when `GEMINI_API_KEY` is set.

```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
```

If Gemini is not configured or the package is missing, the backend falls back to built-in heuristic summary/report generation.

---

## 🛡️ Anomaly Detection Rules

These rules are implemented in `backend/main.py`:

- `HIGH_TRAFFIC` — one IP sending too many packets
- `PORT_SCAN` — one IP probing many unique destination ports
- `SYN_SCAN` — bare SYN packets with no ACK
- `ICMP_FLOOD` — high ICMP packet rate from one IP
- `DNS_FLOOD` — high DNS query rate from one IP
- `BURST_TRAFFIC` — many packets from one IP in a 5-second window

Alert history is persistent in `alert_history`, while `current_alerts` only holds the latest cycle alerts.

---

## 🧠 Frontend Features

- 9 live dashboard cards refreshed every 2 seconds
- Protocol quick filters: TCP / UDP / ICMP / DNS / ARP / ALL
- Tabbed side panel: Inspector, AI, Suspicious, History, Export
- Packet inspector shows:
  - TTL, TCP flags, sequence/ack numbers
  - ICMP type/code
  - DNS query name
  - ARP operation
  - Safe HTTP headers with auth scheme presence only
  - Hex payload preview
- Suspicious IP cards with severity, packet count, ports, protocols, and reason tags
- Alert history panel with reverse-chronological entries
- Export panel for JSON and incident report downloads

---

## 📋 Requirements

- Python 3.9+
- `fastapi`, `uvicorn`, `scapy`, `google-generativeai`, `python-multipart`
- Root/admin privileges for live capture (optional; demo mode works without)
- Modern browser (Chrome, Firefox, Edge)

---

## 🔧 Notes

- `start.sh` installs dependencies if needed.
- Demo mode runs when Scapy is unavailable.
- Use `sudo` for real packet capture.
- Gemini is optional.

---

## 🔒 Security

This tool is intended for monitoring networks you own or have permission to monitor. Unauthorized packet capture may violate local laws.

---

## 🤝 Contributing

1. Fork the repository.
2. Clone your fork.
3. Create a feature branch.
4. Make changes and test.
5. Commit with a clear message.
6. Push your branch and open a PR.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE).

---

## 🐛 Troubleshooting

- Scapy issues: install libpcap (`sudo apt install libpcap-dev`).
- Permission denied: run with `sudo`.
- Port in use: change the port in `start.sh` or the `uvicorn` command.
- Gemini errors: verify `GEMINI_API_KEY` and install `google-generativeai`.

