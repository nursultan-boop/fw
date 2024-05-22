import subprocess

# Module metadata
enabled = False

def enable_module():
    global enabled
    if not enabled:
        # Block common VPN ports (example ports, adjust as needed)
        commands = [
            "sudo iptables -A INPUT -p udp --dport 1194 -j DROP",  # OpenVPN
            "sudo iptables -A INPUT -p tcp --dport 1723 -j DROP",  # PPTP
            "sudo iptables -A INPUT -p udp --dport 500 -j DROP",   # IKEv2
            "sudo iptables -A INPUT -p udp --dport 4500 -j DROP",  # IPsec NAT-T
            "sudo iptables -A INPUT -p tcp --dport 1701 -j DROP",  # L2TP
            "sudo iptables -A INPUT -p udp --dport 1701 -j DROP",  # L2TP
            "sudo iptables -A INPUT -p udp --dport 53 -j DROP"     # DNS
        ]
        for command in commands:
            subprocess.run(command, shell=True)
        enabled = True
        print("VPN blocking enabled.")

def disable_module():
    global enabled
    if enabled:
        # Remove the rules added to block VPN ports
        commands = [
            "sudo iptables -D INPUT -p udp --dport 1194 -j DROP",  # OpenVPN
            "sudo iptables -D INPUT -p tcp --dport 1723 -j DROP",  # PPTP
            "sudo iptables -D INPUT -p udp --dport 500 -j DROP",   # IKEv2
            "sudo iptables -D INPUT -p udp --dport 4500 -j DROP",  # IPsec NAT-T
            "sudo iptables -D INPUT -p tcp --dport 1701 -j DROP",  # L2TP
            "sudo iptables -D INPUT -p udp --dport 1701 -j DROP",  # L2TP
            "sudo iptables -D INPUT -p udp --dport 53 -j DROP"     # DNS
        ]
        for command in commands:
            subprocess.run(command, shell=True)
        enabled = False
        print("VPN blocking disabled.")
