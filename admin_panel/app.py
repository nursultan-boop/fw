import json
import os
import subprocess
import psutil
from flask import Flask, render_template, request, redirect, url_for, jsonify
import random
import time
import importlib.util


app = Flask(__name__)

#region Load data
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
        "bytes_sent": random.randint(1000, 10000),
        "bytes_recv": random.randint(1000, 10000),
        "packets_sent": random.randint(10, 100),
        "packets_recv": random.randint(10, 100)
    }
    return stats

def get_device_logs(device_ip):
    # For demonstration purposes, we return a static log. Replace with actual log retrieval logic.
    return f"Logs for device with IP {device_ip}"
#endregion

#region rules
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
    return render_template('device.html', device_name=device_name, device_ip=device_ip)

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
def device_stats(device_ip):
    stats = get_network_stats(device_ip)
    return jsonify(stats)

#endregion

#region modules

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
            modules.append({
                'name': module_name,
                'enabled': getattr(module, 'enabled', False)
            })
    return modules

@app.route('/module/<module_name>')
def module_page(module_name):
    return render_template(f'module_{module_name}.html')

@app.route('/toggle_module/<module_name>', methods=['POST'])
def toggle_module(module_name):
    try:
        module_path = os.path.join(os.path.dirname(__file__), '../modules', f'{module_name}.py')

        # Verify the module file exists
        if not os.path.isfile(module_path):
            return jsonify(success=False, error=f"Module file not found: {module_path}")

        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if getattr(module, 'enabled', False):
            module.disable_module()
            module.enabled = False
        else:
            module.enable_module()
            module.enabled = True

        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

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
