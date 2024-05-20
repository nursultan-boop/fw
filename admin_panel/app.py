import json
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)

<<<<<<< HEAD
# Directory and file paths
=======
# Load data
>>>>>>> parent of 78ec312 (lets' gooo)
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
<<<<<<< HEAD
    """Scan for connected devices using nmcli."""
    command = "nmcli -t -f DEVICE,IP4.ADDRESS device show"
=======
    """Scan for connected devices using arp-scan."""
    command = "sudo arp-scan --localnet"
>>>>>>> parent of 78ec312 (lets' gooo)
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    devices = []
    for line in output.split('\n'):
<<<<<<< HEAD
        if line:
            parts = line.split(':')
            if len(parts) == 2 and parts[1]:
                device = parts[0]
                ip = parts[1].split('/')[0]
                devices.append({"name": device, "ip": ip})
=======
        if '192.168.' in line:  # Adjust this based on your local network range
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                name = parts[1] if len(parts) > 2 else "Unknown"
                devices.append({"name": name, "ip": ip})
>>>>>>> parent of 78ec312 (lets' gooo)
    return devices

@app.route('/')
def index():
    devices = scan_devices()
    groups = load_data()
    return render_template('index.html', devices=devices, groups=groups)

@app.route('/group/<group_name>')
def group_page(group_name):
    groups = load_data()
    group = groups.get(group_name, {"rules": [], "devices": []})
    devices = scan_devices()
    return render_template('group.html', group_name=group_name, group=group, devices=devices)

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
        del groups[group_name]
        save_data(groups)
    return redirect(url_for('index'))

@app.route('/add_rule/<group_name>', methods=['POST'])
def add_rule(group_name):
    rule = request.form['rule']
    groups = load_data()
    if group_name in groups:
        groups[group_name]['rules'].append(rule)
        save_data(groups)
    return redirect(url_for('group_page', group_name=group_name))

@app.route('/remove_rule/<group_name>/<rule>', methods=['POST'])
def remove_rule(group_name, rule):
    groups = load_data()
    if group_name in groups and rule in groups[group_name]['rules']:
        groups[group_name]['rules'].remove(rule)
        save_data(groups)
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

@app.route('/rename_device', methods=['POST'])
def rename_device():
    device_ip = request.form['device_ip']
    new_name = request.form['new_name']
    groups = load_data()
    devices = scan_devices()
    device_found = False
    
    for group in groups.values():
        for device in group['devices']:
            if device == device_ip:
                device = {"name": new_name, "ip": device_ip}
                device_found = True

    for device in devices:
        if device['ip'] == device_ip:
            device['name'] = new_name
            device_found = True

    if device_found:
        save_data(groups)
    return redirect(url_for('index'))

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

if __name__ == '__main__':
    app.run(debug=True)
