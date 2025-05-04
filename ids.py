#!/usr/bin/env python3

import time
import logging
import argparse
import requests
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, ARP, DNS, DNSRR

# ─── CONFIGURATION ──────────────────────────────────────────────────────────────

# Central server URL
CENTRAL_SERVER = "http://localhost:3000/alert"

# Detection parameters (tweak to your environment)
WINDOW       = 10      # seconds for SYN scan window
THRESHOLD    = 30      # SYNs in WINDOW to trigger
COOL_DOWN    = 300     # seconds between repeated alerts per IP

# Logging setup
logging.basicConfig(
    filename="network_alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ─── STATE ─────────────────────────────────────────────────────────────────────

# ARP table: IP → MAC
arp_table = {}

# SYN scan tracking: src_ip → deque of timestamps
scan_attempts = defaultdict(lambda: deque(maxlen=THRESHOLD + 1))

# Last alert times: src_ip → timestamp
last_alert = {}

# DNS table: domain → set of seen IPs
dns_table = defaultdict(set)


# ─── ALERTING ──────────────────────────────────────────────────────────────────

def send_alert(message, details=None):
    """Send an alert to the central server and log it."""
    logging.info(message)
    print(message)
    payload = {"alert": message}
    if details:
        payload["details"] = details
    try:
        requests.post(CENTRAL_SERVER, json=payload, timeout=3)
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")


# ─── DETECTORS ─────────────────────────────────────────────────────────────────

def detect_mitm(pkt):
    """Detect ARP spoofing (duplicate IP with different MAC)."""
    if pkt.haslayer(ARP) and pkt.op == 2:  # ARP reply
        ip, mac = pkt.psrc, pkt.hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            msg = (
                f"🚨 MITM/ARP SPOOFING DETECTED: {ip} "
                f"was {arp_table[ip]} now {mac}"
            )
            send_alert(msg, {"ip": ip, "macs": [arp_table[ip], mac]})
        arp_table[ip] = mac


def detect_nmap_scan(pkt):
    """Detect SYN flood / Nmap‐style scans."""
    if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x02):  # SYN flag
        now = time.time()
        src = pkt[IP].src
        dq = scan_attempts[src]
        dq.append(now)

        # if window full and time difference within WINDOW
        if len(dq) > THRESHOLD and (now - dq[0] <= WINDOW):
            last = last_alert.get(src, 0)
            if now - last > COOL_DOWN:
                msg = f"🛑 NMAP‐STYLE SCAN DETECTED from {src} (SYNs={len(dq)})"
                send_alert(msg, {"source_ip": src, "syn_count": len(dq)})
                last_alert[src] = now


def detect_dns_spoof(pkt):
    """Simple DNS‐spoof detection: domain resolves to new IP suddenly."""
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).ancount > 0:
        qname = pkt[DNS].qd.qname.decode().rstrip(".")
        answers = {
            rr.rdata for rr in pkt[DNS].an if isinstance(rr, DNSRR)
        }
        seen = dns_table[qname]
        new_ips = answers - seen
        if seen and new_ips:
            msg = (
                f"🛡️ DNS SPOOF DETECTED: {qname} changed from {seen} to {answers}"
            )
            send_alert(msg, {"domain": qname, "old": list(seen), "new": list(answers)})
        dns_table[qname].update(answers)


# ─── MAIN LOOP ────────────────────────────────────────────────────────────────

def process_packet(pkt):
    detect_mitm(pkt)
    detect_nmap_scan(pkt)
    detect_dns_spoof(pkt)


def start_monitoring(interface):
    print(f"[*] Starting IDS on interface: {interface}")
    try:
        # monitor ARP, TCP (for scans), and UDP port 53 (DNS)
        sniff(
            iface=interface,
            store=False,
            filter="arp or tcp or udp port 53",
            prn=process_packet
        )
    except PermissionError:
        print("⚠️  Permission denied: try running with sudo/root.")
    except Exception as e:
        print(f"❌ Error starting sniff: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced IDS: ARP‐MITM, DNS spoof, and Nmap‐scan detection"
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Network interface to monitor (e.g. eth0, wlan0)"
    )
    args = parser.parse_args()
    start_monitoring(args.interface)


if __name__ == "__main__":
    main()

