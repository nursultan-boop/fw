import subprocess
import json
import os

# Paths to data files
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
GROUPS_FILE = os.path.join(DATA_DIR, 'groups.json')

def run_command(command):
    """Run a shell command and return the output."""
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"Error running command: {command}\n{result.stderr.decode()}")
    return result.stdout.decode()

def load_data():
    """Load groups from JSON file."""
    if not os.path.exists(GROUPS_FILE):
        with open(GROUPS_FILE, 'w') as f:
            json.dump({"default": {"rules": [], "devices": []}}, f)
    with open(GROUPS_FILE, 'r') as f:
        groups = json.load(f)
    return groups

def save_data(groups):
    """Save groups to JSON file."""
    with open(GROUPS_FILE, 'w') as f:
        json.dump(groups, f)

def scan_devices():
    """Scan for connected devices using arp-scan."""
    command = "sudo arp-scan --localnet"
    output = run_command(command)
    devices = []
    for line in output.split('\n'):
        if '192.168.' in line:  # Adjust this based on your local network range
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                name = parts[1] if len(parts) > 2 else "Unknown"
                devices.append({"name": name, "ip": ip})
    return devices

def apply_rules():
    """Apply firewall rules based on the current configuration."""
    groups = load_data()

    # Clear existing rules
    run_command('iptables -F')

    # Apply default group rules
    default_group = groups.get('default', {})
    apply_group_rules(default_group.get('rules', []))

    # Apply group-specific rules
    for group_name, group_data in groups.items():
        if group_name != 'default':
            apply_group_rules(group_data.get('rules', []))
            for device_ip in group_data.get('devices', []):
                apply_device_rules(device_ip, group_data.get('rules', []))

def apply_group_rules(rules):
    """Apply rules for a specific group."""
    for rule in rules:
        run_command(f'iptables {rule}')

def apply_device_rules(device_ip, rules):
    """Apply rules for a specific device."""
    for rule in rules:
        run_command(f'iptables -A INPUT -s {device_ip} {rule}')

def add_rule_to_group(group_name, rule):
    """Add a rule to a specific group."""
    groups = load_data()
    groups[group_name]['rules'].append(rule)
    save_data(groups)
    apply_rules()

def remove_rule_from_group(group_name, rule):
    """Remove a rule from a specific group."""
    groups = load_data()
    groups[group_name]['rules'].remove(rule)
    save_data(groups)
    apply_rules()

def add_device_to_group(device_ip, group_name):
    """Add a device to a specific group."""
    groups = load_data()
    for group in groups.values():
        if device_ip in group['devices']:
            group['devices'].remove(device_ip)
    groups[group_name]['devices'].append(device_ip)
    save_data(groups)
    apply_rules()

def remove_device_from_group(device_ip, group_name):
    """Remove a device from a specific group."""
    groups = load_data()
    groups[group_name]['devices'].remove(device_ip)
    groups['default']['devices'].append(device_ip)
    save_data(groups)
    apply_rules()

if __name__ == '__main__':
    # Initial application of rules when the script is run
    apply_rules()
