import subprocess

enabled = False

def enable_module():
    global enabled
    commands = [
        "sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN",
        "sudo iptables -A INPUT -p tcp --syn -j DROP",
        "sudo iptables -A FORWARD -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN",
        "sudo iptables -A FORWARD -p tcp --syn -j DROP",
    ]
    for command in commands:
        subprocess.run(command, shell=True)
    enabled = True
    print("DDoS protection enabled.")

def disable_module():
    global enabled
    commands = [
        "sudo iptables -D INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN",
        "sudo iptables -D INPUT -p tcp --syn -j DROP",
        "sudo iptables -D FORWARD -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN",
        "sudo iptables -D FORWARD -p tcp --syn -j DROP",
    ]
    for command in commands:
        subprocess.run(command, shell=True)
    enabled = False
    print("DDoS protection disabled.")

