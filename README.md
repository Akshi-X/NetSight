# ⬡ NetSight — AI-Powered Packet Analyzer

A web-based network packet analyzer inspired by Wireshark, with real-time capture, anomaly detection, and AI-generated traffic summaries.

---

## 🏗️ Project Structure

```
packet-analyzer/
├── backend/
│   ├── main.py              ← FastAPI app (Scapy + AI)
│   └── requirements.txt
├── frontend/
│   └── index.html           ← Single-file UI (HTML/CSS/JS)
├── start.sh                 ← Quick-start script
└── README.md
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Run the Server

**Demo mode** (no root required — uses simulated packets):
```bash
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

**Live capture mode** (root required for raw socket access):
```bash
sudo python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open in Browser

```
http://localhost:8000
```

---

## 🌐 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/start` | Start packet capture |
| `POST` | `/stop`  | Stop packet capture |
| `GET`  | `/packets?since=N` | Get packets with id > N (incremental) |
| `GET`  | `/packet/{id}` | Get full detail of a single packet |
| `GET`  | `/alerts` | Get current anomaly alerts |
| `POST` | `/summarize` | Generate AI traffic summary |
| `GET`  | `/status` | Get server + capture status |

---

## 🤖 AI Integration (Real LLM)

To use a real AI model instead of the heuristic summary:

### Anthropic Claude
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Then in `backend/main.py`, replace the placeholder in `generate_ai_summary()`:

```python
import anthropic

client = anthropic.Anthropic()
message = client.messages.create(
    model="claude-opus-4-5",
    max_tokens=1024,
    messages=[{
        "role": "user",
        "content": f"""Analyze this network traffic data and provide a security assessment:

Total Packets: {data['total_packets']}
Top IP: {data['top_ip']} ({data['top_ip_count']} packets)
Protocol Distribution: {data['protocol_distribution']}
Alerts: {json.dumps(data['alerts'], indent=2)}

Provide: 1) Traffic summary 2) Anomalies found 3) Security recommendations"""
    }]
)
return message.content[0].text
```

### OpenAI
```bash
export OPENAI_API_KEY=sk-...
```

```python
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role":"user","content": your_prompt}]
)
return response.choices[0].message.content
```

---

## 🛡️ Anomaly Detection Rules

| Rule | Threshold | Alert Type |
|------|-----------|------------|
| High packet volume from one IP | > 20 packets | `HIGH_TRAFFIC` |
| IP probing many ports | > 10 unique ports | `PORT_SCAN` |

Add custom rules in `check_alerts()` in `main.py`.

---

## ⚙️ Configuration

Edit at the top of `backend/main.py`:

```python
# Max packets stored in memory
if len(packets) > 5000:   # change 5000 to your limit
    packets.pop(0)

# Alert thresholds
if count > 20:            # high traffic threshold
if len(ports) > 10:       # port scan threshold
```

---

## 🖥️ UI Features

- **Wireshark-style table** with color-coded protocols (TCP/UDP/ICMP)
- **Incremental polling** — only fetches new packets each cycle
- **Live filter** — filter by IP, port, protocol, keyword
- **Packet inspector** — click any row for full detail + hex payload
- **Alert bar** — real-time anomaly notifications
- **AI analysis** — one-click traffic summary panel
- **Demo mode** — simulates realistic traffic + port scan if Scapy unavailable

---

## 📋 Requirements

- Python 3.9+
- `fastapi`, `uvicorn`, `scapy`
- Root/admin privileges for live capture (optional; demo mode works without)
- Modern browser (Chrome, Firefox, Edge)

---

## 🔒 Security Note

This tool is intended for **network monitoring on networks you own or have permission to monitor**. Unauthorized packet capture may violate laws in your jurisdiction.
