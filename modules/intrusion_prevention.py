import subprocess
import os
import json
from datetime import datetime

# Module metadata
module_name = 'intrusion_prevention'
state_file = os.path.join(os.path.dirname(__file__), '..', 'data', f'{module_name}.json')
log_file = os.path.join(os.path.dirname(__file__), '..', 'data', f'{module_name}_log.json')

# Load the initial state from the JSON file
def load_state():
    if os.path.exists(state_file):
        with open(state_file, 'r') as f:
            state = json.load(f)
            return state.get('enabled', False)
    return False

# Save the current state to the JSON file
def save_state(enabled):
    with open(state_file, 'w') as f:
        json.dump({'enabled': enabled}, f)

# Log an action
def log_action(action, details=""):
    log_entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'action': action,
        'details': details
    }
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = json.load(f)
    else:
        logs = []
    logs.append(log_entry)
    with open(log_file, 'w') as f:
        json.dump(logs, f, indent=4)

# Initialize the enabled state
enabled = load_state()

def enable_module():
    global enabled
    if not enabled:
        # Add iptables rules for intrusion prevention (example rules, adjust as needed)
        commands = [
            "sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set",
            "sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP",
            "sudo iptables -A INPUT -m state --state NEW -m recent --set",
            "sudo iptables -A INPUT -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP"
        ]
        for command in commands:
            subprocess.run(command, shell=True)
        enabled = True
        save_state(enabled)
        log_action("enabled", "Intrusion prevention enabled.")
        print("Intrusion prevention enabled.")

def disable_module():
    global enabled
    if enabled:
        # Remove iptables rules for intrusion prevention
        commands = [
            "sudo iptables -D INPUT -p tcp --dport 22 -m state --state NEW -m recent --set",
            "sudo iptables -D INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP",
            "sudo iptables -D INPUT -m state --state NEW -m recent --set",
            "sudo iptables -D INPUT -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP"
        ]
        for command in commands:
            subprocess.run(command, shell=True)
        enabled = False
        save_state(enabled)
        log_action("disabled", "Intrusion prevention disabled.")
        print("Intrusion prevention disabled.")
