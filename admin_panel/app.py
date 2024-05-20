import json
import os
import subprocess
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
    print("test")
    print(output, flush=True)
    devices = []
    current_device = None  # Store the current device name

    for line in output.split('\n'):
        line = line.strip()  # Remove leading/trailing whitespace

        if line:
            if ':' in line:  # Device name line (ends with ':')
                current_device = line.split(':')[0] # Store device name (remove the ':')
                print(current_device, flush=True)
            elif line.startswith('inet4'):  # IP address line
                ip_address = line.split(' ')[1]
                print(ip_address, flush=True)
                if current_device:  # Ensure we have a valid device name
                    devices.append({"name": current_device, "ip": ip_address})

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
