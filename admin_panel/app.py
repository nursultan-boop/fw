import json
import os
import subprocess
import iptc
import psutil
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)

# Load data
DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
GROUPS_FILE = os.path.join(DATA_DIR, 'groups.json')

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

def load_data():
    if not os.path.exists(GROUPS_FILE):
        with open(GROUPS_FILE, 'w') as f:
            json.dump({"default": {"rules": [], "devices": []}}, f)
    with open(GROUPS_FILE, 'r') as f:
        groups = json.load(f)
    return groups

def save_data(groups):
    with open(GROUPS_FILE, 'w') as f:
        json.dump(groups, f)

def scan_devices():
    """Scan for connected devices using nmcli."""
    command = "nmcli | grep -E 'connected|inet4'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    devices = []
    current_device = None  # Store the current device name

    for line in output.split('\n'):
        line = line.strip()  # Remove leading/trailing whitespace

        if line:
            if ':' in line:  
                current_device = line.split(':')[0] 
            elif line.startswith('inet4'): 
                ip_address = line.split(' ')[1]
                ip = ip_address.split('/')[0]
                if current_device:  
                    devices.append({"name": current_device, "ip": ip})

    return devices

def scan_devices_and_update():
    devices = scan_devices()
    groups = load_data()
    known_ips = {ip for group in groups.values() for ip in group['devices']}
    default_group = groups.setdefault('default', {"rules": [], "devices": []})

    for device in devices:
        if device['ip'] not in known_ips:
            default_group['devices'].append(device['ip'])
    
    save_data(groups)
    return devices

def get_network_stats(device_ip):
    stats = {
        "bytes_sent": 0,
        "bytes_recv": 0,
        "packets_sent": 0,
        "packets_recv": 0
    }
    net_io = psutil.net_io_counters(pernic=True)
    for nic, io in net_io.items():
        if device_ip in nic:
            stats['bytes_sent'] = io.bytes_sent
            stats['bytes_recv'] = io.bytes_recv
            stats['packets_sent'] = io.packets_sent
            stats['packets_recv'] = io.packets_recv
    return stats

def get_device_logs(device_ip):
    # For demonstration purposes, we return a static log. Replace with actual log retrieval logic.
    return f"Logs for device with IP {device_ip}"

def apply_rule(rule):
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule_parts = rule.split()
    iptc_rule = iptc.Rule()

    if rule_parts[0] == "block":
        iptc_rule.target = iptc.Rule.Target(iptc_rule, "DROP")
        if "ip" in rule_parts[1]:
            iptc_rule.src = rule_parts[1]
        elif "domain" in rule_parts[1]:
            # Domain blocking logic
            iptc_rule.dst = rule_parts[1]
        elif "port" in rule_parts[1]:
            match = iptc.Match(iptc_rule, "tcp")
            match.dport = rule_parts[2]
            iptc_rule.add_match(match)
        chain.insert_rule(iptc_rule)

@app.route('/')
def index():
    devices = scan_devices_and_update()
    groups = load_data()
    # Add new devices to the default group if they are not in any group
    for device in devices:
        if not any(device['ip'] in group['devices'] for group in groups.values()):
            groups['default']['devices'].append(device['ip'])
    
    save_data(groups)
    return render_template('index.html', devices=devices, groups=groups)

@app.route('/group/<group_name>')
def group_page(group_name):
    devices = scan_devices_and_update()
    groups = load_data()
    group = groups.get(group_name, {"rules": [], "devices": []})
    return render_template('group.html', group_name=group_name, group=group, devices=devices)

@app.route('/monitor_device/<device_ip>')
def monitor_device(device_ip):
    devices = scan_devices()
    device_name = next((device['name'] for device in devices if device['ip'] == device_ip), 'Unknown')
    stats = get_network_stats(device_ip)
    logs = get_device_logs(device_ip)
    return render_template('device.html', device_name=device_name, device_ip=device_ip, stats=stats, logs=logs)


@app.route('/module/<module_name>')
def module_page(module_name):
    return render_template(f'module_{module_name}.html')

@app.route('/add_group', methods=['GET', 'POST'])
def add_group():
    if request.method == 'POST':
        group_name = request.form['group_name']
        groups = load_data()
        if group_name not in groups:
            groups[group_name] = {"rules": [], "devices": []}
            save_data(groups)
        return redirect(url_for('index'))
    return render_template('add_group.html')

@app.route('/remove_group/<group_name>', methods=['POST'])
def remove_group(group_name):
    groups = load_data()
    if group_name in groups and group_name != 'default':
        # Move devices from the group to the default group
        devices_to_move = groups[group_name]['devices']
        groups['default']['devices'].extend(devices_to_move)        
        del groups[group_name]
        save_data(groups)
    return redirect(url_for('index'))

@app.route('/add_rule/<group_name>', methods=['POST'])
def add_rule(group_name):
    rule_type = request.form['rule_type']
    rule_value = request.form['rule_value']
    rule = f"{rule_type} {rule_value}"
    groups = load_data()
    if group_name in groups:
        groups[group_name]['rules'].append(rule)
        save_data(groups)
        apply_rule(rule)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/remove_rule/<group_name>/<rule>', methods=['POST'])
def remove_rule(group_name, rule):
    groups = load_data()
    if group_name in groups and rule in groups[group_name]['rules']:
        groups[group_name]['rules'].remove(rule)
        save_data(groups)
        # Remove the rule using iptables
        remove_rule_iptables(rule)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/add_device/<group_name>', methods=['POST'])
def add_device(group_name):
    device_ip = request.form['device_ip']
    groups = load_data()
    if group_name in groups:
        # Remove the device from any other group
        for group in groups.values():
            if device_ip in group['devices']:
                group['devices'].remove(device_ip)
        groups[group_name]['devices'].append(device_ip)
        save_data(groups)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/remove_device/<group_name>/<device_ip>', methods=['POST'])
def remove_device(group_name, device_ip):
    groups = load_data()
    if group_name in groups and device_ip in groups[group_name]['devices']:
        groups[group_name]['devices'].remove(device_ip)
        groups['default']['devices'].append(device_ip)
        save_data(groups)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/toggle_module/<module_name>', methods=['POST'])
def toggle_module(module_name):
    # Example toggling logic (you need to implement the actual enabling/disabling logic)
    try:
        module = __import__(f"../modules/{module_name}")
        if getattr(module, 'enabled', False):
            module.disable_module()
            module.enabled = False
        else:
            module.enable_module()
            module.enabled = True
        return jsonify(success=True)
    except ImportError:
        return jsonify(success=False, error="Module not found")

def apply_rule(rule):
    # Apply the rule using iptables
    command = f"iptables {rule}"
    subprocess.run(command, shell=True)

def remove_rule_iptables(rule):
    # Remove the rule using iptables
    command = f"iptables -D {rule}"
    subprocess.run(command, shell=True)

if __name__ == '__main__':
    app.run(debug=True)
