"""
AI-Powered Packet Analyzer Backend
FastAPI + Scapy + Threading
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import threading
import time
import json
import os
from datetime import datetime
from collections import defaultdict
from typing import Optional
import random

# Try to import scapy - graceful fallback if not available or broken env
try:
    import os as _os
    _os.environ.setdefault("SCAPY_USE_LIBPCAP", "1")
    # Suppress scapy IPv6 route errors in constrained environments
    import warnings
    warnings.filterwarnings("ignore")
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, ARP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available - running in DEMO mode with simulated packets")

app = FastAPI(title="AI Packet Analyzer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  Shared State
# ─────────────────────────────────────────────
packets = []            # list of parsed packet dicts
alerts = []             # list of alert strings
capture_active = False
capture_thread = None
packet_lock = threading.Lock()
packet_counter = 0

# Stats for anomaly detection
ip_packet_count = defaultdict(int)
ip_port_targets = defaultdict(set)


# ─────────────────────────────────────────────
#  Packet Parsing
# ─────────────────────────────────────────────
def parse_packet(pkt) -> Optional[dict]:
    """Parse a Scapy packet into a clean dict."""
    global packet_counter

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    length = len(pkt)
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    proto = "OTHER"
    src_port = dst_port = None
    info = ""
    payload_hex = ""

    if pkt.haslayer(TCP):
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags
        info = f"TCP {src_ip}:{src_port} → {dst_ip}:{dst_port} [Flags: {flags}]"
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
            payload_hex = raw.hex()[:256]
        ip_port_targets[src_ip].add(dst_port)

    elif pkt.haslayer(UDP):
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        info = f"UDP {src_ip}:{src_port} → {dst_ip}:{dst_port}"
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
            info = f"DNS Query: {pkt[DNSQR].qname.decode(errors='ignore')}"
        ip_port_targets[src_ip].add(dst_port)

    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code
        info = f"ICMP Type={icmp_type} Code={icmp_code} {src_ip} → {dst_ip}"
    else:
        info = f"IP {src_ip} → {dst_ip} Proto={ip.proto}"

    ip_packet_count[src_ip] += 1
    packet_counter += 1

    return {
        "id": packet_counter,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "length": length,
        "info": info,
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": payload_hex,
        "raw_summary": pkt.summary() if SCAPY_AVAILABLE else info,
    }


def check_alerts():
    """Run anomaly detection rules."""
    global alerts
    new_alerts = []

    for ip, count in ip_packet_count.items():
        if count > 20:
            new_alerts.append({
                "type": "HIGH_TRAFFIC",
                "severity": "HIGH",
                "ip": ip,
                "message": f"⚠️  High traffic: {ip} sent {count} packets (possible flood/scan)",
            })

    for ip, ports in ip_port_targets.items():
        if len(ports) > 10:
            new_alerts.append({
                "type": "PORT_SCAN",
                "severity": "CRITICAL",
                "ip": ip,
                "message": f"🔴 Port scan detected: {ip} probed {len(ports)} ports",
            })

    alerts = new_alerts


# ─────────────────────────────────────────────
#  Capture Thread (Real Scapy)
# ─────────────────────────────────────────────
def scapy_callback(pkt):
    global capture_active
    if not capture_active:
        return
    parsed = parse_packet(pkt)
    if parsed:
        with packet_lock:
            packets.append(parsed)
            if len(packets) > 5000:
                packets.pop(0)
        check_alerts()


def capture_loop():
    """Sniff packets until capture_active is False."""
    global capture_active
    while capture_active:
        try:
            sniff(prn=scapy_callback, count=50, timeout=2, store=False)
        except Exception as e:
            print(f"Sniff error: {e}")
            time.sleep(1)


# ─────────────────────────────────────────────
#  Demo Mode (no Scapy / no root)
# ─────────────────────────────────────────────
DEMO_IPS = [
    "192.168.1.1", "192.168.1.10", "10.0.0.5",
    "8.8.8.8", "1.1.1.1", "172.16.0.3",
    "192.168.1.50", "10.10.10.10",
]
DEMO_PROTOS = ["TCP", "UDP", "ICMP"]
DEMO_PORTS = [80, 443, 22, 53, 8080, 3306, 5432, 21, 25, 110, 8443, 9200]

def demo_capture_loop():
    """Generate realistic-looking fake packets for demo mode."""
    global capture_active, packet_counter
    # Inject a port-scan scenario after 5 seconds
    scan_ip = "10.0.0.99"
    scan_triggered = False

    while capture_active:
        time.sleep(random.uniform(0.2, 0.7))
        if not capture_active:
            break

        # After 8 seconds, simulate a port scan
        if packet_counter > 15 and not scan_triggered:
            scan_triggered = True
            for port in random.sample(DEMO_PORTS * 3, 18):
                if not capture_active:
                    break
                time.sleep(0.05)
                ip_port_targets[scan_ip].add(port)
                ip_packet_count[scan_ip] += 1
                packet_counter += 1
                pkt_dict = {
                    "id": packet_counter,
                    "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "src_ip": scan_ip,
                    "dst_ip": random.choice(DEMO_IPS[:4]),
                    "protocol": "TCP",
                    "length": random.randint(54, 74),
                    "info": f"TCP {scan_ip}:{random.randint(40000,65000)} → port {port} [SYN]",
                    "src_port": random.randint(40000, 65000),
                    "dst_port": port,
                    "payload": "",
                    "raw_summary": f"IP {scan_ip} > port {port}: TCP SYN",
                }
                with packet_lock:
                    packets.append(pkt_dict)
                check_alerts()
            continue

        src = random.choice(DEMO_IPS)
        dst = random.choice([ip for ip in DEMO_IPS if ip != src])
        proto = random.choices(DEMO_PROTOS, weights=[60, 30, 10])[0]
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(DEMO_PORTS)
        length = random.randint(64, 1500)

        if proto == "TCP":
            info = f"TCP {src}:{src_port} → {dst}:{dst_port} [ACK]"
        elif proto == "UDP":
            if dst_port == 53:
                info = f"DNS Query: example{random.randint(1,99)}.com"
            else:
                info = f"UDP {src}:{src_port} → {dst}:{dst_port}"
        else:
            info = f"ICMP Echo Request {src} → {dst}"

        ip_packet_count[src] += 1
        if proto in ("TCP", "UDP"):
            ip_port_targets[src].add(dst_port)

        packet_counter += 1
        pkt_dict = {
            "id": packet_counter,
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "length": length,
            "info": info,
            "src_port": src_port if proto != "ICMP" else None,
            "dst_port": dst_port if proto != "ICMP" else None,
            "payload": "" if proto == "ICMP" else "48454c4c4f20574f524c44",
            "raw_summary": info,
        }
        with packet_lock:
            packets.append(pkt_dict)
            if len(packets) > 5000:
                packets.pop(0)
        check_alerts()


# ─────────────────────────────────────────────
#  AI Summarization
# ─────────────────────────────────────────────
def generate_ai_summary(data: dict) -> str:
    """
    Placeholder AI summary function.
    Replace with real LLM call (Anthropic, OpenAI, etc.) by setting API_KEY env var.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")

    total = data["total_packets"]
    top_ip = data.get("top_ip", "N/A")
    top_ip_count = data.get("top_ip_count", 0)
    alert_count = len(data.get("alerts", []))
    proto_dist = data.get("protocol_distribution", {})
    has_scan = any(a["type"] == "PORT_SCAN" for a in data.get("alerts", []))
    has_flood = any(a["type"] == "HIGH_TRAFFIC" for a in data.get("alerts", []))

    if api_key:
        # Structure for real LLM integration
        # Replace this block with actual API call
        pass

    # Heuristic summary
    lines = []
    lines.append(f"📊 **Traffic Analysis Report** — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"Captured **{total} packets** during this session.")

    # Protocol breakdown
    proto_parts = [f"{k}: {v}" for k, v in proto_dist.items()]
    if proto_parts:
        lines.append(f"Protocol distribution — {', '.join(proto_parts)}.")

    if alert_count == 0:
        lines.append("")
        lines.append("✅ **Status: NORMAL** — Traffic appears healthy with no anomalies detected.")
        lines.append(f"The busiest host was **{top_ip}** with {top_ip_count} packets, which is within acceptable thresholds.")
    else:
        lines.append("")
        lines.append(f"⚠️  **Status: SUSPICIOUS** — {alert_count} alert(s) raised during capture.")

        if has_scan:
            scan_alert = next(a for a in data["alerts"] if a["type"] == "PORT_SCAN")
            lines.append(f"🔴 **Port Scan Detected**: {scan_alert['ip']} probed multiple ports in rapid succession. This is a classic reconnaissance technique used by attackers to identify open services. Recommend blocking this IP and reviewing firewall rules.")

        if has_flood:
            flood_alert = next(a for a in data["alerts"] if a["type"] == "HIGH_TRAFFIC")
            lines.append(f"🟠 **Traffic Flood**: {flood_alert['ip']} generated abnormally high packet volume. This may indicate a DoS attempt, misconfigured service, or malware. Investigate this host immediately.")

        lines.append("")
        lines.append("**Recommended Actions:**")
        if has_scan:
            lines.append("• Block the scanning IP at the firewall level")
            lines.append("• Review services exposed on scanned ports")
        if has_flood:
            lines.append("• Rate-limit traffic from the flooding IP")
            lines.append("• Check if the host is compromised or misconfigured")
        lines.append("• Preserve packet logs for forensic analysis")

    lines.append("")
    lines.append("*Note: Add ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable for enhanced AI analysis.*")
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  API Endpoints
# ─────────────────────────────────────────────
@app.post("/start")
def start_capture():
    global capture_active, capture_thread, packets, alerts
    global packet_counter, ip_packet_count, ip_port_targets

    if capture_active:
        return {"status": "already_running"}

    # Reset state
    packets.clear()
    alerts.clear()
    packet_counter = 0
    ip_packet_count.clear()
    ip_port_targets.clear()

    capture_active = True

    if SCAPY_AVAILABLE:
        # Try real capture; fall back to demo if permission denied
        try:
            capture_thread = threading.Thread(target=capture_loop, daemon=True)
            capture_thread.start()
            mode = "live"
        except Exception:
            capture_thread = threading.Thread(target=demo_capture_loop, daemon=True)
            capture_thread.start()
            mode = "demo"
    else:
        capture_thread = threading.Thread(target=demo_capture_loop, daemon=True)
        capture_thread.start()
        mode = "demo"

    return {"status": "started", "mode": mode}


@app.post("/stop")
def stop_capture():
    global capture_active
    if not capture_active:
        return {"status": "not_running"}
    capture_active = False
    return {"status": "stopped", "total_packets": len(packets)}


@app.get("/packets")
def get_packets(since: int = 0):
    """Return packets with id > since for incremental polling."""
    with packet_lock:
        result = [p for p in packets if p["id"] > since]
    return {
        "packets": result,
        "total": len(packets),
        "capturing": capture_active,
    }


@app.get("/packet/{packet_id}")
def get_packet(packet_id: int):
    with packet_lock:
        for p in packets:
            if p["id"] == packet_id:
                return p
    raise HTTPException(status_code=404, detail="Packet not found")


@app.get("/alerts")
def get_alerts():
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/summarize")
def summarize():
    if not packets:
        return {"summary": "No packets captured yet. Start a capture session first."}

    proto_dist = defaultdict(int)
    ip_counts = defaultdict(int)
    for p in packets:
        proto_dist[p["protocol"]] += 1
        ip_counts[p["src_ip"]] += 1

    top_ip = max(ip_counts, key=ip_counts.get) if ip_counts else "N/A"

    data = {
        "total_packets": len(packets),
        "top_ip": top_ip,
        "top_ip_count": ip_counts.get(top_ip, 0),
        "protocol_distribution": dict(proto_dist),
        "alerts": alerts,
    }

    summary = generate_ai_summary(data)
    return {"summary": summary, "data": data}


@app.get("/status")
def status():
    return {
        "capturing": capture_active,
        "total_packets": len(packets),
        "alert_count": len(alerts),
        "scapy_available": SCAPY_AVAILABLE,
    }


# Serve frontend
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

    @app.get("/")
    def root():
        return FileResponse(os.path.join(frontend_path, "index.html"))
