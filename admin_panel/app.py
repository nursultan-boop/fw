from flask import Flask, render_template, request, redirect, url_for, jsonify
import json
import os
import subprocess

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
    """Scan for connected devices using arp-scan."""
    command = "sudo arp-scan --localnet"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    devices = []
    for line in output.split('\n'):
        if '192.168.' in line:  # Adjust this based on your local network range
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                name = parts[1] if len(parts) > 2 else "Unknown"
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
    return render_template(f'module_{module_name}.html')

# Add more routes and handlers for add, remove, edit, etc.

if __name__ == '__main__':
    app.run(debug=True)
