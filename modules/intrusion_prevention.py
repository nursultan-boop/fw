from scapy.all import sniff, IP, TCP, UDP
import json
import os
import time
from collections import defaultdict
import threading

data_dir = os.path.join(os.path.dirname(__file__), 'data')
log_file = os.path.join(data_dir, 'intrusion_prevention_log.json')
devices_file = os.path.join(data_dir, 'devices.json')

failed_login_attempts = defaultdict(int)
high_traffic_counts = defaultdict(int)
enabled_event = threading.Event()  # Event to control module state

def load_devices():
    if os.path.exists(devices_file):
        with open(devices_file, 'r') as f:
            return json.load(f)
    return []

def write_log(entry):
    logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = json.load(f)
    logs.append(entry)
    with open(log_file, 'w') as f:
        json.dump(logs, f)

def detect_attack(packet):
    if not enabled_event.is_set():
        return
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
         
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            flags = packet[TCP].flags
            # Detect Port Scanning
            if tcp_layer.flags & 0x02:
                print(f"SYN packet detected: {ip_src} -> {ip_dst}:{tcp_layer.dport}")  # Debug print
                log_entry = {
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                    'source_ip': ip_src,
                    'destination_ip': ip_dst,
                    'protocol': 'TCP',
                    'action': 'Detected',
                    'reason': f'SYN packet detected on port {tcp_layer.dport}'
                }
                write_log(log_entry)
            # Detect Brute Force Login Attempts (example for SSH)
            if dport ==22 and packet[TCP].flags == "S":
                failed_login_attempts[ip_src] += 1
                if failed_login_attempts[ip_src] > 5:
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
            if high_traffic_counts[(ip_src, ip_dst, dport)] > 100:
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

                

        

def start_sniffing(interface):
    print(f"Starting sniffing on {interface}")
    sniff(prn=detect_attack, store=0, iface=interface)

def enable_module():
    enabled_event.set()
    print("Intrusion detection module enabled")

def disable_module():
    enabled_event.clear()
    print("Intrusion detection module disabled")

if __name__ == "__main__":
    interface = "enp0s3"  # Update with your interface name
    enabled_event.set()
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.start()

    while True:
        time.sleep(1)
