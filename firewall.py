import os
import importlib
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

devices = {}
groups = {}
rules = {}
modules = {}
active_modules = {}

# Load modules
modules_dir = './modules'
for filename in os.listdir(modules_dir):
    if filename.endswith('.py'):
        module_name = filename[:-3]
        module = importlib.import_module(f'modules.{module_name}')
        modules[module_name] = module
        active_modules[module_name] = False

def get_network_devices():
    """Get network devices grouped by their connections."""
    devices.clear()
    result = subprocess.run(['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION,IP4.ADDRESS', 'device'], stdout=subprocess.PIPE)
    lines = result.stdout.decode().strip().split('\n')

    for line in lines:
        if ':' not in line:
            continue
        device, dtype, state, connection, ip = line.split(':')
        if connection not in devices:
            devices[connection] = []
        devices[connection].append({
            'name': connection,
            'device': device,
            'type': dtype,
            'state': state,
            'ip': ip
        })

    return devices

@app.route('/devices', methods=['GET'])
def get_devices():
    devices = get_network_devices()
    return jsonify(devices)

@app.route('/groups', methods=['GET', 'POST', 'PUT', 'DELETE'])
def manage_groups():
    if request.method == 'POST':
        group_name = request.json['name']
        if group_name not in groups:
            groups[group_name] = {'devices': [], 'rules': []}
            return jsonify({'status': 'Group added'}), 201
        else:
            return jsonify({'status': 'Group already exists'}), 400
    elif request.method == 'PUT':
        old_name = request.json['old_name']
        new_name = request.json['new_name']
        if old_name in groups:
            groups[new_name] = groups.pop(old_name)
            return jsonify({'status': 'Group renamed'}), 200
        else:
            return jsonify({'status': 'Group not found'}), 404
    elif request.method == 'DELETE':
        group_name = request.json['name']
        if group_name in groups:
            del groups[group_name]
            return jsonify({'status': 'Group deleted'}), 200
        else:
            return jsonify({'status': 'Group not found'}), 404
    return jsonify(groups)

@app.route('/groups/assign', methods=['POST'])
def assign_device_to_group():
    group_name = request.json['group']
    device_name = request.json['device']
    if group_name in groups:
        if device_name not in groups[group_name]['devices']:
            groups[group_name]['devices'].append(device_name)
            return jsonify({'status': 'Device assigned to group'}), 200
        else:
            return jsonify({'status': 'Device already in group'}), 400
    else:
        return jsonify({'status': 'Group not found'}), 404

@app.route('/groups/remove_device', methods=['POST'])
def remove_device_from_group():
    group_name = request.json['group']
    device_name = request.json['device']
    if group_name in groups:
        if device_name in groups[group_name]['devices']:
            groups[group_name]['devices'].remove(device_name)
            return jsonify({'status': 'Device removed from group'}), 200
        else:
            return jsonify({'status': 'Device not in group'}), 400
    else:
        return jsonify({'status': 'Group not found'}), 404

@app.route('/rules', methods=['GET', 'POST', 'DELETE'])
def manage_rules():
    if request.method == 'POST':
        group_name = request.json['group']
        rule = request.json['rule']
        if group_name in groups:
            groups[group_name]['rules'].append(rule)
            update_firewall_rules()
            return jsonify({'status': 'Rule added'}), 201
    elif request.method == 'DELETE':
        group_name = request.json['group']
        rule = request.json['rule']
        if group_name in groups and rule in groups[group_name]['rules']:
            groups[group_name]['rules'].remove(rule)
            update_firewall_rules()
            return jsonify({'status': 'Rule removed'}), 200
    return jsonify(groups)

@app.route('/modules', methods=['GET', 'POST'])
def manage_modules():
    if request.method == 'POST':
        module_name = request.json['module']
        action = request.json['action']
        if module_name in modules:
            if action == 'enable':
                active_modules[module_name] = True
                modules[module_name].enable()
                return jsonify({'status': 'Module enabled'}), 200
            elif action == 'disable':
                active_modules[module_name] = False
                modules[module_name].disable()
                return jsonify({'status': 'Module disabled'}), 200
        return jsonify({'status': 'Module not found'}), 404
    return jsonify(active_modules)

def update_firewall_rules():
    # Placeholder function to update firewall rules
    # Add actual iptables update logic here
    print("Updating firewall rules based on current group configurations.")
    # Example command: subprocess.run(['iptables', '-A', 'INPUT', '-s', '1.1.1.1', '-j', 'DROP'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
