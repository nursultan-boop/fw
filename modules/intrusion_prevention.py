from scapy.all import sniff, IP, TCP, UDP
import json
import os
import time
from collections import defaultdict

log_file = 'data/intrusion_prevention_log.json'

# Track IP and port activity
failed_login_attempts = defaultdict(int)
high_traffic_counts = defaultdict(int)

def write_log(entry):
    logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = json.load(f)
    logs.append(entry)
    with open(log_file, 'w') as f:
        json.dump(logs, f)

def detect_attack(packet):
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            sport = packet[TCP].sport
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport
            sport = packet[UDP].sport

        # Detect Port Scanning
        if packet.haslayer(TCP) and packet[TCP].flags == "S":  # SYN flag
            log_entry = {
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                'source_ip': ip_src,
                'destination_ip': ip_dst,
                'protocol': 'TCP',
                'action': 'Blocked',
                'reason': f'Port scan detected on port {dport}'
            }
            write_log(log_entry)
            print(f"Port scan detected from {ip_src} to {ip_dst}:{dport}")

        # Detect Brute Force Login Attempts (example for SSH)
        if packet.haslayer(TCP) and dport == 22:  # SSH port
            if packet[TCP].flags == "S":  # SYN flag (connection attempt)
                failed_login_attempts[ip_src] += 1
                if failed_login_attempts[ip_src] > 5:  # Threshold for brute force detection
                    log_entry = {
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                        'source_ip': ip_src,
                        'destination_ip': ip_dst,
                        'protocol': 'TCP',
                        'action': 'Blocked',
                        'reason': f'Brute force login attempt detected on port {dport}'
                    }
                    write_log(log_entry)
                    print(f"Brute force login attempt detected from {ip_src} to {ip_dst}:{dport}")

        # Detect DoS Attacks
        high_traffic_counts[(ip_src, ip_dst, dport)] += 1
        if high_traffic_counts[(ip_src, ip_dst, dport)] > 100:  # Threshold for high traffic detection
            log_entry = {
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                'source_ip': ip_src,
                'destination_ip': ip_dst,
                'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP',
                'action': 'Blocked',
                'reason': f'Possible DoS attack detected on port {dport}'
            }
            write_log(log_entry)
            print(f"Possible DoS attack detected from {ip_src} to {ip_dst}:{dport}")

# Sniffing on the network interface (e.g., eth0)
sniff(prn=detect_attack, filter="ip", store=0, iface="eth0")
