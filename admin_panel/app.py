import json
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for, jsonify
import importlib.util
from scapy.all import sniff
from threading import Thread
from collections import defaultdict
import random
import time

app = Flask(__name__)

#region Load data
DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
GROUPS_FILE = os.path.join(DATA_DIR, 'groups.json')
device_stats = {}

def get_module_state(module_name):
    state_file = os.path.join(DATA_DIR, f'{module_name}.json')
    if os.path.exists(state_file):
        with open(state_file, 'r') as f:
            state = json.load(f)
            return state.get('enabled', False)
    return False

def get_module_logs(module_name):
    log_file = os.path.join(DATA_DIR, f'{module_name}_log.json')
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = json.load(f)
            return logs
    return []

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

log_file = os.path.join(DATA_DIR, 'intrusion_prevention_log.json')

def write_log(entry):
    logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = json.load(f)
    logs.append(entry)
    with open(log_file, 'w') as f:
        json.dump(logs, f)

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

def packet_callback(packet):
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        log_entry = packet.summary()
        print(log_entry)
        if ip_src not in device_stats:
            device_stats[ip_src] = {"bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0, "logs": []}
        if ip_dst not in device_stats:
            device_stats[ip_dst] = {"bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0, "logs": []}

        device_stats[ip_src]["bytes_sent"] += len(packet)
        device_stats[ip_src]["packets_sent"] += 1
        device_stats[ip_src]["logs"].append(log_entry)

        device_stats[ip_dst]["bytes_recv"] += len(packet)
        device_stats[ip_dst]["packets_recv"] += 1
        device_stats[ip_dst]["logs"].append(log_entry)
sniffer_thread = None
def start_sniffer(interface):
    try:
        print("Starting sniffer on interface", interface)
        sniff(prn=packet_callback, store=0, iface = interface)
        time.sleep(1)
        sniffer_thread.join()
    except Exception as e:
        print(f"Error starting sniffer: {e}")

#endregion

#region rules

@app.route('/add_rule/<group_name>', methods=['GET', 'POST'])
def add_rule(group_name):
    if request.method == 'POST':
        rule_type = request.form['rule_type']
        rule_value = request.form['rule_value']
        groups = load_data()

        if group_name in groups:
            rule = {"type": rule_type, "value": rule_value}
            groups[group_name]['rules'].append(rule)
            apply_rule(rule)
            save_data(groups)

        return redirect(url_for('group_page', group_name=group_name))
    return render_template('add_rule.html', group_name=group_name)

@app.route('/remove_rule/<group_name>/<rule_index>', methods=['POST'])
def remove_rule(group_name, rule_index):
    groups = load_data()
    rule_index = int(rule_index)
    if group_name in groups and rule_index < len(groups[group_name]['rules']):
        rule = groups[group_name]['rules'].pop(rule_index)
        remove_iptables_rule(rule)
        save_data(groups)
    return redirect(url_for('group_page', group_name=group_name))

def remove_iptables_rule(rule):
    if rule['type'] == 'block_ip':
        command = f"sudo iptables -D FORWARD -s {rule['value']} -j DROP"
    elif rule['type'] == 'block_domain':
        ip = resolve_domain_to_ip(rule['value'])
        command = f"sudo iptables -D FORWARD -s {ip} -j DROP"
    elif rule['type'] == 'block_port':
        command = f"sudo iptables -D FORWARD -p tcp --dport {rule['value']} -j DROP"
    else:
        return
    subprocess.run(command, shell=True)

def resolve_domain_to_ip(domain):
    result = subprocess.run(['nslookup', domain], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    for line in output.split('\n'):
        if 'Address: ' in line:
            return line.split(' ')[1]
    return None

def apply_rule(rule):
    if rule['type'] == 'block_ip':
        command = f"sudo iptables -A FORWARD -s {rule['value']} -j REJECT"
    elif rule['type'] == 'block_domain':
        # Assuming you have a method to resolve domain to IP
        ip = resolve_domain_to_ip(rule['value'])
        command = f"sudo iptables -A FORWARD -s {ip} -j REJECT"
    elif rule['type'] == 'block_port':
        command = f"sudo iptables -A FORWARD -p tcp --dport {rule['value']} -j REJECT"
    else:
        return
    subprocess.run(command, shell=True)

def resolve_domain_to_ip(domain):
    result = subprocess.run(['nslookup', domain], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    for line in output.split('\n'):
        if 'Address: ' in line:
            return line.split(' ')[1]
    return None

def remove_rule_iptables(rule):
    # Remove the rule using iptables
    command = f"iptables -D {rule}"
    subprocess.run(command, shell=True)
#endregion

#region groups
@app.route('/group/<group_name>')
def group_page(group_name):
    devices = scan_devices_and_update()
    groups = load_data()
    group = groups.get(group_name, {"rules": [], "devices": []})
    return render_template('group.html', group_name=group_name, group=group, devices=devices)

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


#endregion

#region devices

@app.route('/monitor_device/<device_ip>')
def monitor_device(device_ip):
    devices = scan_devices()
    device_name = next((device['name'] for device in devices if device['ip'] == device_ip), 'Unknown')
    return render_template('device.html', device_name=device_name, device_ip=device_ip, logs=[])

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

@app.route('/device_stats/<device_ip>')
def device_stats_route(device_ip):
    try:
        devices = scan_devices()
        interface = next((device['name'] for device in devices if device['ip'] == device_ip), 'Unknown')
        print("Starting application")
        global sniffer_thread
        if sniffer_thread: 
            sniffer_thread.join()
        sniffer_thread = Thread(target=start_sniffer, args=(interface,))
        sniffer_thread.daemon = True
        sniffer_thread.start()
        print("Sniffer thread started")
    except Exception as e:
        print(f"Error starting sniffer thread: {e}")
    stats = device_stats.get(device_ip, {
        "bytes_sent": 0,
        "bytes_recv": 0,
        "packets_sent": 0,
        "packets_recv": 0,
        "logs": []
    })
    return jsonify(stats)

#endregion

#region modules

@app.route('/module_logs/<module_name>', methods=['GET'])
def module_logs(module_name):
    logs = get_module_logs(module_name)
    return jsonify(logs=logs)

def discover_modules():
    modules_dir = os.path.join(os.path.dirname(__file__), '../modules')
    modules = []
    
    for filename in os.listdir(modules_dir):
        if filename.endswith('.py'):
            module_name = filename[:-3]
            module_path = os.path.join(modules_dir, filename)
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            enabled = get_module_state(module_name)
            modules.append({
                'name': module_name,
                'enabled': enabled
            })
    return modules

@app.route('/get_latest_logs')
def get_latest_logs():
    logs = get_module_logs('intrusion_prevention')
    logs = sorted(logs, key=lambda log: log['timestamp'], reverse=True)
    return jsonify(logs)

@app.route('/module/<module_name>')
def module_page(module_name):
    logs = get_module_logs(module_name)
    return render_template(f'module_{module_name}.html', logs=logs)

@app.route('/toggle_module/<module_name>', methods=['POST'])
def toggle_module(module_name):
    module_path = os.path.join(os.path.dirname(__file__), '../modules', f'{module_name}.py')
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    
    enabled = get_module_state(module_name)

    if enabled:
        module.disable_module()
        enabled = False
        
    else:
        module.enable_module()
        enabled = True
        

    with open(os.path.join(DATA_DIR, f'{module_name}.json'), 'w') as f:
        json.dump({'enabled': enabled}, f)

    return jsonify(success=True)



#endregion

@app.route('/')
def index():
    devices = scan_devices_and_update()
    groups = load_data()
    modules = discover_modules()
    # Add new devices to the default group if they are not in any group
    for device in devices:
        if not any(device['ip'] in group['devices'] for group in groups.values()):
            groups['default']['devices'].append(device['ip'])
    
    save_data(groups)
    return render_template('index.html', devices=devices, groups=groups, modules=modules)

if __name__ == '__main__':
    
    app.run(debug=True)
