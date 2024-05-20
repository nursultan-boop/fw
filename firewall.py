import json
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)

# Load data
DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
GROUPS_FILE = os.path.join(DATA_DIR, 'groups.json')
DEVICES_FILE = os.path.join(DATA_DIR, 'devices.json')
MODULES_FILE = os.path.join(DATA_DIR, 'modules.json')

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

def load_data():
    if not os.path.exists(GROUPS_FILE):
        with open(GROUPS_FILE, 'w') as f:
            json.dump({"default": {"rules": [], "devices": []}}, f)
    if not os.path.exists(DEVICES_FILE):
        with open(DEVICES_FILE, 'w') as f:
            json.dump({}, f)
    if not os.path.exists(MODULES_FILE):
        with open(MODULES_FILE, 'w') as f:
            json.dump({"example_module": False}, f)  # Assume example_module is initially off
    
    with open(GROUPS_FILE, 'r') as f:
        groups = json.load(f)
    with open(DEVICES_FILE, 'r') as f:
        devices = json.load(f)
    with open(MODULES_FILE, 'r') as f:
        modules = json.load(f)
    
    return groups, devices, modules

def save_data(groups, devices, modules):
    with open(GROUPS_FILE, 'w') as f:
        json.dump(groups, f)
    with open(DEVICES_FILE, 'w') as f:
        json.dump(devices, f)
    with open(MODULES_FILE, 'w') as f:
        json.dump(modules, f)

def scan_devices():
    """Scan for connected devices using nmcli."""
    command = "nmcli -t -f DEVICE,IP4.ADDRESS device show"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    devices = []
    for line in output.split('\n'):
        if line:
            parts = line.split(':')
            if len(parts) == 2 and parts[1]:
                device = parts[0]
                ip = parts[1].split('/')[0]
                devices.append({"name": device, "ip": ip})
    return devices

@app.route('/')
def index():
    scanned_devices = scan_devices()
    groups, devices, modules = load_data()
    
    # Update device names from saved data
    for device in scanned_devices:
        if device['ip'] in devices:
            device['name'] = devices[device['ip']]
    
    return render_template('index.html', devices=scanned_devices, groups=groups, modules=modules)

@app.route('/rename_device', methods=['POST'])
def rename_device():
    device_ip = request.form['device_ip']
    new_name = request.form['new_name']
    _, devices, _ = load_data()
    devices[device_ip] = new_name
    save_data(_, devices, _)
    return redirect(url_for('index'))

@app.route('/group/<group_name>')
def group_page(group_name):
    groups, devices, _ = load_data()
    group = groups.get(group_name, {"rules": [], "devices": []})
    scanned_devices = scan_devices()
    
    # Update device names from saved data
    for device in scanned_devices:
        if device['ip'] in devices:
            device['name'] = devices[device['ip']]
    
    return render_template('group.html', group_name=group_name, group=group, devices=scanned_devices)

@app.route('/module/<module_name>')
def module_page(module_name):
    return render_template(f'module_{module_name}.html')

@app.route('/add_group', methods=['GET', 'POST'])
def add_group():
    if request.method == 'POST':
        group_name = request.form['group_name']
        groups, _, _ = load_data()
        if group_name not in groups:
            groups[group_name] = {"rules": [], "devices": []}
            save_data(groups, _, _)
        return redirect(url_for('index'))
    return render_template('add_group.html')

@app.route('/remove_group/<group_name>', methods=['POST'])
def remove_group(group_name):
    groups, _, _ = load_data()
    if group_name in groups and group_name != 'default':
        default_group = groups['default']
        for device_ip in groups[group_name]['devices']:
            default_group['devices'].append(device_ip)
        del groups[group_name]
        save_data(groups, _, _)
    return redirect(url_for('index'))

@app.route('/add_rule/<group_name>', methods=['POST'])
def add_rule(group_name):
    rule_type = request.form['rule_type']
    value = request.form['value']
    groups, _, _ = load_data()
    if group_name in groups:
        rule = f"{rule_type} {value}"
        groups[group_name]['rules'].append(rule)
        save_data(groups, _, _)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/remove_rule/<group_name>/<rule>', methods=['POST'])
def remove_rule(group_name, rule):
    groups, _, _ = load_data()
    if group_name in groups and rule in groups[group_name]['rules']:
        groups[group_name]['rules'].remove(rule)
        save_data(groups, _, _)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/add_device/<group_name>', methods=['POST'])
def add_device(group_name):
    device_ip = request.form['device_ip']
    groups, devices, _ = load_data()
    if group_name in groups:
        # Remove the device from any other group
        for group in groups.values():
            if device_ip in group['devices']:
                group['devices'].remove(device_ip)
        groups[group_name]['devices'].append(device_ip)
        save_data(groups, devices, _)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/remove_device/<group_name>/<device_ip>', methods=['POST'])
def remove_device(group_name, device_ip):
    groups, _, _ = load_data()
    if group_name in groups and device_ip in groups[group_name]['devices']:
        groups[group_name]['devices'].remove(device_ip)
        groups['default']['devices'].append(device_ip)
        save_data(groups, _, _)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/toggle_module/<module_name>', methods=['POST'])
def toggle_module(module_name):
    _, _, modules = load_data()
    # Example toggling logic (you need to implement the actual enabling/disabling logic)
    if module_name in modules:
        modules[module_name] = not modules[module_name]
        save_data(_, _, modules)
        return jsonify(success=True, status=modules[module_name])
    return jsonify(success=False, error="Module not found")

if __name__ == '__main__':
    app.run(debug=True)
