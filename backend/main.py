"""
NetSight — AI-Powered Packet Analyzer  |  Enhanced Backend
FastAPI + Scapy + Gemini AI
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import threading
import time
import json
import os
from datetime import datetime
from collections import defaultdict
from typing import Optional
import random

# ─────────────────────────────────────────────
#  Scapy — graceful fallback
# ─────────────────────────────────────────────
try:
    import os as _os
    _os.environ.setdefault("SCAPY_USE_LIBPCAP", "1")
    import warnings
    warnings.filterwarnings("ignore")
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, ARP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available — running in DEMO mode")

app = FastAPI(title="NetSight AI Packet Analyzer", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  Shared State
# ─────────────────────────────────────────────
packets        = []          # parsed packet dicts (max 5000)
alert_history  = []          # persistent alert history (all alerts ever fired)
capture_active = False
capture_thread = None
packet_lock    = threading.Lock()
packet_counter = 0

# Per-IP tracking for anomaly detection
ip_packet_count   = defaultdict(int)          # src_ip → total packets
ip_port_targets   = defaultdict(set)          # src_ip → set of dst ports contacted
ip_icmp_count     = defaultdict(int)          # src_ip → ICMP packet count
ip_dns_count      = defaultdict(int)          # src_ip → DNS query count
ip_syn_count      = defaultdict(int)          # src_ip → TCP SYN count
ip_first_seen     = {}                        # src_ip → first timestamp
ip_last_seen      = {}                        # src_ip → last timestamp
ip_protocols      = defaultdict(set)          # src_ip → set of protocols used
ip_burst_window   = defaultdict(list)         # src_ip → list of timestamps (for burst detection)

# Suspicious IP tracker: ip → {reason, packet_count, ports, severity, ...}
suspicious_ips    = {}

# Current active alerts (latest check)
current_alerts    = []

# ─────────────────────────────────────────────
#  Gemini AI Helper
# ─────────────────────────────────────────────
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

def call_gemini(prompt: str, model: str = "gemini-1.5-flash") -> str:
    """
    Call Google Gemini API with the given prompt.
    Returns the response text, or empty string on failure.
    Requires: pip install google-generativeai
    """
    if not GEMINI_API_KEY:
        return ""
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        m = genai.GenerativeModel(model)
        response = m.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini API error: {e}")
        return ""


# ─────────────────────────────────────────────
#  Packet Parsing
# ─────────────────────────────────────────────
def parse_packet(pkt) -> Optional[dict]:
    """Parse a Scapy packet into a rich detail dict."""
    global packet_counter

    if not pkt.haslayer(IP):
        return None

    ip        = pkt[IP]
    src_ip    = ip.src
    dst_ip    = ip.dst
    length    = len(pkt)
    ttl       = ip.ttl
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    now_ts    = time.time()

    proto       = "OTHER"
    src_port    = dst_port = None
    info        = ""
    payload_hex = ""

    # Extra fields for rich inspector
    tcp_flags    = None
    tcp_seq      = None
    tcp_ack_num  = None
    dns_query    = None
    arp_info     = None
    http_info    = None
    icmp_type    = None
    icmp_code    = None

    if pkt.haslayer(TCP):
        proto    = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags    = pkt[TCP].flags
        tcp_flags   = str(flags)
        tcp_seq     = pkt[TCP].seq
        tcp_ack_num = pkt[TCP].ack
        info     = f"TCP {src_ip}:{src_port} → {dst_ip}:{dst_port} [{flags}]"

        # Count SYN packets (no ACK) for SYN scan detection
        if 'S' in str(flags) and 'A' not in str(flags):
            ip_syn_count[src_ip] += 1

        if pkt.haslayer(Raw):
            raw         = bytes(pkt[Raw])
            payload_hex = raw.hex()[:256]
            # Safe HTTP header inspection (no credentials extracted)
            try:
                decoded = raw.decode('utf-8', errors='ignore')
                if decoded.startswith(('GET ','POST ','PUT ','DELETE ','HEAD ','OPTIONS ')):
                    lines = decoded.split('\r\n')
                    method_line = lines[0] if lines else ""
                    parts = method_line.split(' ')
                    http_info = {
                        "method":       parts[0] if len(parts) > 0 else "",
                        "path":         parts[1] if len(parts) > 1 else "",
                        "host":         next((l.split(':',1)[1].strip() for l in lines if l.lower().startswith('host:')), ""),
                        "user_agent":   next((l.split(':',1)[1].strip() for l in lines if l.lower().startswith('user-agent:')), ""),
                        "content_type": next((l.split(':',1)[1].strip() for l in lines if l.lower().startswith('content-type:')), ""),
                        "auth_scheme":  "Present (redacted)" if any(
                            l.lower().startswith(('authorization:','cookie:')) for l in lines
                        ) else "None",
                        "note": "HTTPS traffic is encrypted — content not visible without decryption."
                                if dst_port == 443 else ""
                    }
            except Exception:
                pass

        ip_port_targets[src_ip].add(dst_port)

    elif pkt.haslayer(UDP):
        proto    = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        info     = f"UDP {src_ip}:{src_port} → {dst_ip}:{dst_port}"

        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
            qname     = pkt[DNSQR].qname.decode(errors='ignore')
            dns_query = qname
            info      = f"DNS Query: {qname}"
            ip_dns_count[src_ip] += 1

        ip_port_targets[src_ip].add(dst_port)

    elif pkt.haslayer(ICMP):
        proto      = "ICMP"
        icmp_type  = pkt[ICMP].type
        icmp_code  = pkt[ICMP].code
        info       = f"ICMP Type={icmp_type} Code={icmp_code}  {src_ip} → {dst_ip}"
        ip_icmp_count[src_ip] += 1

    elif pkt.haslayer(ARP):
        proto    = "ARP"
        arp_op   = "Request" if pkt[ARP].op == 1 else "Reply"
        arp_info = {
            "operation":  arp_op,
            "sender_mac": pkt[ARP].hwsrc,
            "sender_ip":  pkt[ARP].psrc,
            "target_mac": pkt[ARP].hwdst,
            "target_ip":  pkt[ARP].pdst,
        }
        info = f"ARP {arp_op}: {pkt[ARP].psrc} → {pkt[ARP].pdst}"
    else:
        info = f"IP {src_ip} → {dst_ip}  Proto={ip.proto}"

    # Update per-IP tracking
    ip_packet_count[src_ip]  += 1
    ip_protocols[src_ip].add(proto)
    ip_first_seen.setdefault(src_ip, timestamp)
    ip_last_seen[src_ip]      = timestamp

    # Burst window tracking (sliding 5-second window)
    ip_burst_window[src_ip].append(now_ts)
    ip_burst_window[src_ip] = [t for t in ip_burst_window[src_ip] if now_ts - t < 5.0]

    packet_counter += 1

    return {
        "id":          packet_counter,
        "timestamp":   timestamp,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    proto,
        "length":      length,
        "info":        info,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "payload":     payload_hex,
        "raw_summary": pkt.summary() if SCAPY_AVAILABLE else info,
        # Enriched inspector fields
        "ttl":         ttl,
        "tcp_flags":   tcp_flags,
        "tcp_seq":     tcp_seq,
        "tcp_ack":     tcp_ack_num,
        "dns_query":   dns_query,
        "arp_info":    arp_info,
        "http_info":   http_info,
        "icmp_type":   icmp_type,
        "icmp_code":   icmp_code,
    }


# ─────────────────────────────────────────────
#  Anomaly Detection — Enhanced Rules
# ─────────────────────────────────────────────
def _add_alert(alert_type: str, severity: str, ip: str, message: str):
    """Add alert to both current_alerts and persistent alert_history."""
    entry = {
        "type":      alert_type,
        "severity":  severity,
        "ip":        ip,
        "message":   message,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    # Avoid duplicate consecutive alerts of the same type for same IP
    existing = next(
        (a for a in current_alerts if a["type"] == alert_type and a["ip"] == ip), None
    )
    if not existing:
        current_alerts.append(entry)
        alert_history.append(entry)
        # Update suspicious IPs tracker
        _update_suspicious_ip(ip, alert_type, severity, message)


def _update_suspicious_ip(ip: str, reason: str, severity: str, message: str):
    """Update the suspicious IPs tracker with latest info."""
    if ip not in suspicious_ips:
        suspicious_ips[ip] = {
            "ip":             ip,
            "reasons":        [],
            "packet_count":   ip_packet_count.get(ip, 0),
            "unique_ports":   len(ip_port_targets.get(ip, set())),
            "severity":       severity,
            "first_seen":     ip_first_seen.get(ip, "—"),
            "last_seen":      ip_last_seen.get(ip, "—"),
            "protocols":      list(ip_protocols.get(ip, set())),
        }
    entry = suspicious_ips[ip]
    if reason not in entry["reasons"]:
        entry["reasons"].append(reason)
    # Escalate severity if needed
    sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    if sev_rank.get(severity, 0) > sev_rank.get(entry["severity"], 0):
        entry["severity"] = severity
    # Refresh live stats
    entry["packet_count"] = ip_packet_count.get(ip, 0)
    entry["unique_ports"] = len(ip_port_targets.get(ip, set()))
    entry["last_seen"]    = ip_last_seen.get(ip, "—")
    entry["protocols"]    = list(ip_protocols.get(ip, set()))


def check_alerts():
    """Run all anomaly detection rules and update current_alerts."""
    global current_alerts
    current_alerts = []  # Reset for this cycle; history is preserved in alert_history

    for ip, count in ip_packet_count.items():
        # Rule 1: High volume from single IP
        if count > 20:
            _add_alert(
                "HIGH_TRAFFIC", "HIGH", ip,
                f"⚠️  High traffic: {ip} sent {count} packets"
            )

        # Rule 2: Port scan — probing many unique ports
        ports = ip_port_targets.get(ip, set())
        if len(ports) > 10:
            _add_alert(
                "PORT_SCAN", "CRITICAL", ip,
                f"🔴 Port scan: {ip} probed {len(ports)} ports"
            )

        # Rule 3: SYN scan — many SYN packets without ACK
        if ip_syn_count.get(ip, 0) > 15:
            _add_alert(
                "SYN_SCAN", "CRITICAL", ip,
                f"🔴 SYN scan: {ip} sent {ip_syn_count[ip]} bare SYN packets"
            )

        # Rule 4: ICMP flood
        if ip_icmp_count.get(ip, 0) > 20:
            _add_alert(
                "ICMP_FLOOD", "HIGH", ip,
                f"⚠️  ICMP flood: {ip} sent {ip_icmp_count[ip]} ICMP packets"
            )

        # Rule 5: DNS flood
        if ip_dns_count.get(ip, 0) > 30:
            _add_alert(
                "DNS_FLOOD", "MEDIUM", ip,
                f"🟡 DNS flood: {ip} made {ip_dns_count[ip]} DNS queries"
            )

        # Rule 6: Burst traffic — many packets in 5-second window
        burst = len(ip_burst_window.get(ip, []))
        if burst > 40:
            _add_alert(
                "BURST_TRAFFIC", "HIGH", ip,
                f"⚠️  Burst traffic: {ip} sent {burst} packets in last 5s"
            )


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
    global capture_active
    while capture_active:
        try:
            sniff(prn=scapy_callback, count=50, timeout=2, store=False)
        except Exception as e:
            print(f"Sniff error: {e}")
            time.sleep(1)


# ─────────────────────────────────────────────
#  Demo Mode
# ─────────────────────────────────────────────
DEMO_IPS   = [
    "192.168.1.1","192.168.1.10","10.0.0.5",
    "8.8.8.8","1.1.1.1","172.16.0.3",
    "192.168.1.50","10.10.10.10",
]
DEMO_PROTOS = ["TCP","UDP","ICMP"]
DEMO_PORTS  = [80,443,22,53,8080,3306,5432,21,25,110,8443,9200]

def demo_capture_loop():
    global capture_active, packet_counter
    scan_ip       = "10.0.0.99"
    scan_triggered = False

    while capture_active:
        time.sleep(random.uniform(0.2, 0.7))
        if not capture_active:
            break

        # After ~15 packets, inject a port scan
        if packet_counter > 15 and not scan_triggered:
            scan_triggered = True
            for port in random.sample(DEMO_PORTS * 3, 18):
                if not capture_active:
                    break
                time.sleep(0.05)
                ip_port_targets[scan_ip].add(port)
                ip_packet_count[scan_ip] += 1
                ip_syn_count[scan_ip]    += 1
                ip_protocols[scan_ip].add("TCP")
                ip_first_seen.setdefault(scan_ip, datetime.now().strftime("%H:%M:%S.%f")[:-3])
                ip_last_seen[scan_ip] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                ip_burst_window[scan_ip].append(time.time())

                packet_counter += 1
                pkt_dict = {
                    "id":        packet_counter,
                    "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "src_ip":    scan_ip,
                    "dst_ip":    random.choice(DEMO_IPS[:4]),
                    "protocol":  "TCP",
                    "length":    random.randint(54, 74),
                    "info":      f"TCP {scan_ip}:{random.randint(40000,65000)} → port {port} [SYN]",
                    "src_port":  random.randint(40000,65000),
                    "dst_port":  port,
                    "payload":   "",
                    "raw_summary": f"IP {scan_ip} > port {port}: TCP SYN",
                    "ttl": 64, "tcp_flags": "S", "tcp_seq": random.randint(1000,9999),
                    "tcp_ack": None, "dns_query": None, "arp_info": None,
                    "http_info": None, "icmp_type": None, "icmp_code": None,
                }
                with packet_lock:
                    packets.append(pkt_dict)
                check_alerts()
            continue

        src      = random.choice(DEMO_IPS)
        dst      = random.choice([ip for ip in DEMO_IPS if ip != src])
        proto    = random.choices(DEMO_PROTOS, weights=[60,30,10])[0]
        src_port = random.randint(1024,65535)
        dst_port = random.choice(DEMO_PORTS)
        length   = random.randint(64,1500)
        now_ts   = time.time()
        ts       = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        dns_query  = None
        icmp_t = icmp_c = None
        tcp_flags_demo = None

        if proto == "TCP":
            tcp_flags_demo = random.choice(["A","S","FA","PA"])
            info = f"TCP {src}:{src_port} → {dst}:{dst_port} [{tcp_flags_demo}]"
            if "S" in tcp_flags_demo and "A" not in tcp_flags_demo:
                ip_syn_count[src] += 1
            ip_port_targets[src].add(dst_port)
        elif proto == "UDP":
            if dst_port == 53:
                dns_query = f"example{random.randint(1,99)}.com"
                info = f"DNS Query: {dns_query}"
                ip_dns_count[src] += 1
            else:
                info = f"UDP {src}:{src_port} → {dst}:{dst_port}"
            ip_port_targets[src].add(dst_port)
        else:
            icmp_t = 8; icmp_c = 0
            info = f"ICMP Echo Request  {src} → {dst}"
            ip_icmp_count[src] += 1

        ip_packet_count[src]  += 1
        ip_protocols[src].add(proto)
        ip_first_seen.setdefault(src, ts)
        ip_last_seen[src] = ts
        ip_burst_window[src].append(now_ts)
        ip_burst_window[src] = [t for t in ip_burst_window[src] if now_ts - t < 5.0]

        packet_counter += 1
        pkt_dict = {
            "id":        packet_counter,
            "timestamp": ts,
            "src_ip":    src, "dst_ip": dst,
            "protocol":  proto, "length": length, "info": info,
            "src_port":  src_port if proto != "ICMP" else None,
            "dst_port":  dst_port if proto != "ICMP" else None,
            "payload":   "" if proto == "ICMP" else "48454c4c4f20574f524c44",
            "raw_summary": info,
            "ttl":       random.randint(32,128),
            "tcp_flags": tcp_flags_demo,
            "tcp_seq":   random.randint(1000,99999) if proto == "TCP" else None,
            "tcp_ack":   random.randint(1000,99999) if proto == "TCP" else None,
            "dns_query": dns_query,
            "arp_info":  None,
            "http_info": None,
            "icmp_type": icmp_t,
            "icmp_code": icmp_c,
        }
        with packet_lock:
            packets.append(pkt_dict)
            if len(packets) > 5000:
                packets.pop(0)
        check_alerts()


# ─────────────────────────────────────────────
#  AI Summarization + Report (Gemini / Fallback)
# ─────────────────────────────────────────────
def build_traffic_data() -> dict:
    """Aggregate stats from current capture for AI or export."""
    proto_dist = defaultdict(int)
    ip_counts  = defaultdict(int)
    port_counts= defaultdict(int)
    for p in packets:
        proto_dist[p["protocol"]] += 1
        ip_counts[p["src_ip"]]    += 1
        if p.get("dst_port"):
            port_counts[p["dst_port"]] += 1

    top_ip   = max(ip_counts,   key=ip_counts.get)   if ip_counts   else "N/A"
    top_port = max(port_counts, key=port_counts.get) if port_counts else "N/A"

    return {
        "total_packets":         len(packets),
        "top_ip":                top_ip,
        "top_ip_count":          ip_counts.get(top_ip, 0),
        "top_port":              top_port,
        "protocol_distribution": dict(proto_dist),
        "alerts":                current_alerts,
        "alert_history_count":   len(alert_history),
        "suspicious_ip_count":   len(suspicious_ips),
        "timestamp":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def generate_ai_summary(data: dict, mode: str = "concise") -> str:
    """Generate AI summary using Gemini if key present, else heuristic fallback."""

    # ── Gemini path ──
    if GEMINI_API_KEY:
        detail = "detailed" if mode == "detailed" else "concise"
        prompt = f"""You are a cybersecurity analyst. Analyze the following network traffic data and provide a {detail} security assessment.

Traffic Data:
- Total Packets: {data['total_packets']}
- Top Talker IP: {data['top_ip']} ({data['top_ip_count']} packets)
- Most Targeted Port: {data['top_port']}
- Protocol Distribution: {json.dumps(data['protocol_distribution'])}
- Active Alerts: {json.dumps(data['alerts'], indent=2)}
- Suspicious IPs Tracked: {data['suspicious_ip_count']}

Provide:
1. Traffic summary (2-3 sentences)
2. Anomalies / threats detected
3. Security recommendations (bullet points)
4. Overall severity: NORMAL / LOW / MEDIUM / HIGH / CRITICAL

Keep response clear, technical, and actionable. Use markdown-style bold for key terms."""

        result = call_gemini(prompt)
        if result:
            return result

    # ── Heuristic fallback ──
    total       = data["total_packets"]
    top_ip      = data.get("top_ip", "N/A")
    top_ip_cnt  = data.get("top_ip_count", 0)
    alert_count = len(data.get("alerts", []))
    proto_dist  = data.get("protocol_distribution", {})
    has_scan    = any(a["type"] in ("PORT_SCAN","SYN_SCAN")  for a in data.get("alerts",[]))
    has_flood   = any(a["type"] in ("HIGH_TRAFFIC","ICMP_FLOOD","DNS_FLOOD","BURST_TRAFFIC") for a in data.get("alerts",[]))

    lines = [
        f"📊 **Traffic Analysis Report** — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Captured **{total} packets** during this session.",
        f"Protocol distribution — {', '.join(f'{k}: {v}' for k,v in proto_dist.items())}.",
    ]

    if alert_count == 0:
        lines += [
            "",
            "✅ **Status: NORMAL** — No anomalies detected.",
            f"Busiest host: **{top_ip}** with {top_ip_cnt} packets — within normal thresholds.",
        ]
    else:
        lines += ["", f"⚠️  **Status: SUSPICIOUS** — {alert_count} alert(s) raised."]
        if has_scan:
            a = next(x for x in data["alerts"] if x["type"] in ("PORT_SCAN","SYN_SCAN"))
            lines.append(f"🔴 **Scan Detected**: {a['ip']} — {a['message']}")
        if has_flood:
            a = next(x for x in data["alerts"] if x["type"] in ("HIGH_TRAFFIC","ICMP_FLOOD","DNS_FLOOD","BURST_TRAFFIC"))
            lines.append(f"🟠 **Flood Detected**: {a['ip']} — {a['message']}")
        lines += [
            "",
            "**Recommended Actions:**",
            "• Block suspicious IPs at the firewall level",
            "• Review exposed services on scanned ports",
            "• Rate-limit traffic from flooding IPs",
            "• Preserve packet logs for forensic analysis",
        ]

    if not GEMINI_API_KEY:
        lines.append("\n*Set GEMINI_API_KEY for AI-powered analysis.*")
    return "\n".join(lines)


def generate_incident_report(data: dict) -> str:
    """Generate a full incident/security report (Gemini or heuristic)."""

    sus_list = list(suspicious_ips.values())

    if GEMINI_API_KEY:
        prompt = f"""You are a senior SOC analyst. Generate a formal incident report for the following network capture session.

Session Summary:
- Timestamp: {data['timestamp']}
- Total Packets: {data['total_packets']}
- Protocol Distribution: {json.dumps(data['protocol_distribution'])}
- Top Talker: {data['top_ip']} ({data['top_ip_count']} pkts)
- Most Targeted Port: {data['top_port']}

Suspicious IPs ({len(sus_list)} total):
{json.dumps(sus_list, indent=2)}

Alerts Fired ({len(alert_history)} total):
{json.dumps(alert_history[-20:], indent=2)}

Generate a professional incident report with:
1. Executive Summary
2. Traffic Overview
3. Threat Analysis (per suspicious IP if any)
4. Protocol Anomalies
5. Recommendations
6. Conclusion & Severity Rating

Format clearly with section headers."""

        result = call_gemini(prompt, model="gemini-1.5-pro")
        if result:
            return result

    # Heuristic report
    lines = [
        "=" * 60,
        "  NETSIGHT — SECURITY INCIDENT REPORT",
        f"  Generated: {data['timestamp']}",
        "=" * 60,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        f"Total packets analysed: {data['total_packets']}",
        f"Alerts triggered: {len(alert_history)}",
        f"Suspicious IPs identified: {len(sus_list)}",
        "",
        "PROTOCOL DISTRIBUTION",
        "-" * 40,
    ]
    for proto, cnt in data["protocol_distribution"].items():
        pct = round(cnt / max(data["total_packets"], 1) * 100, 1)
        lines.append(f"  {proto:<8} {cnt:>6} packets  ({pct}%)")

    lines += ["", "TOP TALKERS", "-" * 40,
              f"  Most active source: {data['top_ip']} ({data['top_ip_count']} packets)",
              f"  Most targeted port: {data['top_port']}"]

    if sus_list:
        lines += ["", "SUSPICIOUS IPs", "-" * 40]
        for s in sus_list:
            lines.append(f"  IP: {s['ip']}")
            lines.append(f"    Reasons:        {', '.join(s['reasons'])}")
            lines.append(f"    Severity:       {s['severity']}")
            lines.append(f"    Packets sent:   {s['packet_count']}")
            lines.append(f"    Ports targeted: {s['unique_ports']}")
            lines.append(f"    Protocols:      {', '.join(s['protocols'])}")
            lines.append(f"    First seen:     {s['first_seen']}")
            lines.append(f"    Last seen:      {s['last_seen']}")
            lines.append("")

    lines += [
        "RECOMMENDATIONS",
        "-" * 40,
        "  1. Block all CRITICAL-severity IPs at firewall",
        "  2. Review and tighten port exposure",
        "  3. Enable rate limiting for UDP/DNS traffic",
        "  4. Monitor identified IPs for continued activity",
        "  5. Retain packet capture logs for forensic review",
        "",
        "=" * 60,
        "  END OF REPORT — NetSight v2.0",
        "=" * 60,
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  API Endpoints
# ─────────────────────────────────────────────

@app.post("/start")
def start_capture():
    global capture_active, capture_thread, packets, current_alerts, alert_history
    global packet_counter, ip_packet_count, ip_port_targets
    global ip_icmp_count, ip_dns_count, ip_syn_count
    global ip_first_seen, ip_last_seen, ip_protocols, ip_burst_window, suspicious_ips

    if capture_active:
        return {"status": "already_running"}

    # Reset all state
    packets.clear(); current_alerts.clear(); alert_history.clear()
    packet_counter = 0
    for d in (ip_packet_count, ip_port_targets, ip_icmp_count, ip_dns_count,
              ip_syn_count, ip_first_seen, ip_last_seen, ip_protocols,
              ip_burst_window, suspicious_ips):
        d.clear()

    capture_active = True
    mode           = "demo"

    if SCAPY_AVAILABLE:
        try:
            capture_thread = threading.Thread(target=capture_loop, daemon=True)
            capture_thread.start()
            mode = "live"
        except Exception:
            capture_thread = threading.Thread(target=demo_capture_loop, daemon=True)
            capture_thread.start()
    else:
        capture_thread = threading.Thread(target=demo_capture_loop, daemon=True)
        capture_thread.start()

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
    with packet_lock:
        result = [p for p in packets if p["id"] > since]
    return {"packets": result, "total": len(packets), "capturing": capture_active}


@app.get("/packet/{packet_id}")
def get_packet(packet_id: int):
    with packet_lock:
        for p in packets:
            if p["id"] == packet_id:
                return p
    raise HTTPException(status_code=404, detail="Packet not found")


@app.get("/alerts")
def get_alerts():
    return {"alerts": current_alerts, "count": len(current_alerts)}


@app.get("/alert-history")
def get_alert_history():
    return {"alerts": alert_history, "count": len(alert_history)}


@app.get("/dashboard")
def get_dashboard():
    """Aggregate dashboard stats for the live stat cards."""
    proto_dist = defaultdict(int)
    ip_counts  = defaultdict(int)
    port_counts= defaultdict(int)
    for p in packets:
        proto_dist[p["protocol"]] += 1
        ip_counts[p["src_ip"]]    += 1
        if p.get("dst_port"):
            port_counts[p["dst_port"]] += 1

    top_ip   = max(ip_counts,   key=ip_counts.get)   if ip_counts   else "—"
    top_port = max(port_counts, key=port_counts.get) if port_counts else "—"

    return {
        "total_packets":    len(packets),
        "tcp_count":        proto_dist.get("TCP", 0),
        "udp_count":        proto_dist.get("UDP", 0),
        "icmp_count":       proto_dist.get("ICMP", 0),
        "dns_count":        sum(ip_dns_count.values()),
        "arp_count":        proto_dist.get("ARP", 0),
        "alert_count":      len(current_alerts),
        "top_talker_ip":    top_ip,
        "top_port":         top_port,
        "suspicious_count": len(suspicious_ips),
        "capturing":        capture_active,
    }


@app.get("/suspicious-ips")
def get_suspicious_ips():
    return {"ips": list(suspicious_ips.values()), "count": len(suspicious_ips)}


@app.post("/summarize")
def summarize(mode: str = "concise"):
    if not packets:
        return {"summary": "No packets captured yet. Start a capture session first."}
    data    = build_traffic_data()
    summary = generate_ai_summary(data, mode=mode)
    return {"summary": summary, "data": data}


@app.post("/report")
def generate_report():
    if not packets:
        return {"report": "No packets captured yet."}
    data   = build_traffic_data()
    report = generate_incident_report(data)
    return {"report": report, "data": data}


@app.get("/status")
def status():
    return {
        "capturing":       capture_active,
        "total_packets":   len(packets),
        "alert_count":     len(current_alerts),
        "scapy_available": SCAPY_AVAILABLE,
        "gemini_enabled":  bool(GEMINI_API_KEY),
    }


# ── Export Endpoints ──

@app.get("/export/packets")
def export_packets():
    """Export all captured packets as JSON."""
    with packet_lock:
        data = list(packets)
    return JSONResponse(content={"packets": data, "count": len(data),
                                  "exported_at": datetime.now().isoformat()})


@app.get("/export/alerts")
def export_alerts():
    """Export full alert history as JSON."""
    return JSONResponse(content={"alerts": alert_history, "count": len(alert_history),
                                  "exported_at": datetime.now().isoformat()})


@app.get("/export/suspicious-ips")
def export_suspicious_ips():
    """Export suspicious IP tracker data as JSON."""
    return JSONResponse(content={"suspicious_ips": list(suspicious_ips.values()),
                                  "count": len(suspicious_ips),
                                  "exported_at": datetime.now().isoformat()})


@app.post("/export/report")
def export_report():
    """Generate and return incident report as plain text."""
    data   = build_traffic_data()
    report = generate_incident_report(data)
    return JSONResponse(content={"report": report,
                                  "exported_at": datetime.now().isoformat()})


# ── Serve frontend ──
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

    @app.get("/")
    def root():
        return FileResponse(os.path.join(frontend_path, "index.html"))
