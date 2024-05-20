from flask import Flask, render_template, request, redirect, url_for, jsonify
import json
import os
import subprocess

app = Flask(__name__)


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
    """Scan for connected devices using arp."""
    command = "arp -a"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    devices = []
    for line in output.split('\n'):
        if '(' in line and ')' in line:
            parts = line.split()
            ip = parts[1].strip('()')
            name = parts[0] if parts[0] != '?' else 'Unknown'
            devices.append({"name": name, "ip": ip})

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
    return render_template(f'{module_name}.html')

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
        # Move devices to default group before deletion
        default_group = groups['default']['devices']
        for device in groups[group_name]['devices']:
            if device not in default_group:
                default_group.append(device)
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

@app.route('/add_device/<group_name>/<device_ip>', methods=['POST'])
def add_device(group_name, device_ip):
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
    result = toggle_module(module_name)
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)