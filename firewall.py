# firewall.py
import os
import importlib
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# Data Storage (Consider using a database for persistence)
devices = {}  
groups = {}
rules = {}
modules = {}
active_modules = {}

# Load Modules (Dynamic Loading & Security)
modules_dir = './modules'
for filename in os.listdir(modules_dir):
    if filename.endswith('.py'):
        module_name = filename[:-3]
        try:
            module = importlib.import_module(f'modules.{module_name}')
            modules[module_name] = module
            active_modules[module_name] = False
        except Exception as e:
            print(f"Error loading module '{module_name}': {e}") 

def get_network_devices():
    """Get network devices grouped by their connections."""
    devices.clear()
    result = subprocess.run(['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'device'], stdout=subprocess.PIPE)
    lines = result.stdout.decode().strip().split('\n')

    for line in lines:
        device, dtype, state, connection = line.split(':')
        if connection not in devices:
            devices[connection] = []
        devices[connection].append({
            'device': device,
            'type': dtype,
            'state': state,
        })
    return devices

# API Endpoints

@app.route('/devices', methods=['GET'])
def get_devices():
    devices = get_network_devices()
    return jsonify(devices)

@app.route('/groups', methods=['GET', 'POST', 'PUT', 'DELETE'])
def manage_groups():
    if request.method == 'POST':
        group_name = request.json.get('name')
        if not group_name:
            return jsonify({'status': 'Group name is required'}), 400

        if group_name not in groups:
            groups[group_name] = []
            return jsonify({'status': 'Group added'}), 201
        else:
            return jsonify({'status': 'Group already exists'}), 400

    elif request.method == 'PUT':
        old_name = request.json.get('old_name')
        new_name = request.json.get('new_name')
        if not old_name or not new_name:
            return jsonify({'status': 'Old and new group names are required'}), 400

        if old_name in groups:
            groups[new_name] = groups.pop(old_name)
            return jsonify({'status': 'Group renamed'}), 200
        else:
            return jsonify({'status': 'Group not found'}), 404

    elif request.method == 'DELETE':
        group_name = request.json.get('name')
        if not group_name:
            return jsonify({'status': 'Group name is required'}), 400

        if group_name in groups:
            del groups[group_name]
            return jsonify({'status': 'Group deleted'}), 200
        else:
            return jsonify({'status': 'Group not found'}), 404

    return jsonify(groups)

@app.route('/groups/assign', methods=['POST'])
def assign_device_to_group():
    group_name = request.json.get('group')
    device = request.json.get('device')
    if not group_name or not device:
        return jsonify({'status': 'Group name and device are required'}), 400

    if group_name in groups:
        if device not in groups[group_name]:
            groups[group_name].append(device)
            return jsonify({'status': 'Device assigned to group'}), 200
        else:
            return jsonify({'status': 'Device already in group'}), 400
    else:
        return jsonify({'status': 'Group not found'}), 404

@app.route('/rules', methods=['GET', 'POST', 'DELETE'])
def manage_rules():
    if request.method == 'POST':
        group_name = request.json.get('group')
        rule_type = request.json.get('rule_type') 
        rule_value = request.json.get('rule_value')

        if not all([group_name, rule_type, rule_value]):
            return jsonify({'status': 'Group name, rule type, and rule value are required'}), 400

        if group_name not in rules:
            rules[group_name] = []

        # Basic input validation (you should make this more robust)
        if rule_type in ['BLOCK_IP', 'ALLOW_IP']:
            # Validate IP address format (use a regex or library)
            pass 
        elif rule_type in ['BLOCK_PORT', 'ALLOW_PORT']:
            # Validate port number (must be an integer within a valid range)
            pass 
        elif rule_type in ['BLOCK_DOMAIN', 'ALLOW_DOMAIN']:
            # Validate domain name format (use a regex or library)
            pass

        # Construct and execute iptables command
        if rule_type.startswith('BLOCK'):
            action = '-A INPUT -s' if rule_type == 'BLOCK_IP' else '-A INPUT -p'
            if rule_type in ['BLOCK_IP', 'BLOCK_DOMAIN']:
                rule = f'{action} {rule_value} -j DROP'
            else:
                protocol = 'tcp' if 'tcp' in rule_value.lower() else 'udp'
                rule = f'{action} {protocol} --dport {rule_value} -j DROP'
        else:  # ALLOW rules
            action = '-I INPUT -s' if rule_type == 'ALLOW_IP' else '-I INPUT -p'
            if rule_type in ['ALLOW_IP', 'ALLOW_DOMAIN']:
                rule = f'{action} {rule_value} -j ACCEPT'
            else:
                protocol = 'tcp' if 'tcp' in rule_value.lower() else 'udp'
                rule = f'{action} {protocol} --dport {rule_value} -j ACCEPT'

        try:
            subprocess.run(['iptables', *rule.split()], check=True)
            rules[group_name].append(rule)
            return jsonify({'status': 'Rule added', 'rule': rule}), 201
        except subprocess.CalledProcessError as e:
            return jsonify({'status': 'Error adding rule', 'error': str(e)}), 500

    elif request.method == 'DELETE':
        group_name = request.json.get('group')
        rule_to_delete = request.json.get('rule')

        if not group_name or not rule_to_delete:
            return jsonify({'status': 'Group name and rule are required'}), 400

        if group_name in rules:
            if rule_to_delete in rules[group_name]:
                rules[group_name].remove(rule_to_delete)
                # Remove rule from iptables
                try:
                    subprocess.run(['iptables', '-D', *rule_to_delete.split()], check=True)
                    return jsonify({'status': 'Rule deleted'}), 200
                except subprocess.CalledProcessError as e:
                    return jsonify({'status': 'Error deleting rule', 'error': str(e)}), 500
            else:
                return jsonify({'status': 'Rule not found in group'}), 404
        else:
            return jsonify({'status': 'Group not found'}), 404
    return jsonify(rules)

@app.route('/modules', methods=['GET', 'POST'])
def manage_modules():
    if request.method == 'POST':
        module_name = request.json.get('module')
        action = request.json.get('action')
        
        if not module_name or not action:
            return jsonify({'status': 'Module name and action are required'}), 400
        
        if module_name in modules:
            if action == 'enable':
                if not active_modules[module_name]: 
                    try:
                        modules[module_name].enable()
                        active_modules[module_name] = True
                        return jsonify({'status': 'Module enabled'}), 200
                    except Exception as e:
                        return jsonify({'status': f'Error enabling module: {e}'}), 500
                else:
                    return jsonify({'status': 'Module already enabled'}), 400

            elif action == 'disable':
                if active_modules[module_name]:
                    try:
                        modules[module_name].disable()
                        active_modules[module_name] = False
                        return jsonify({'status': 'Module disabled'}), 200
                    except Exception as e:
                        return jsonify({'status': f'Error disabling module: {e}'}), 500 
                else:
                    return jsonify({'status': 'Module already disabled'}), 400

            else:
                return jsonify({'status': 'Invalid action'}), 400
        else:
            return jsonify({'status': 'Module not found'}), 404
    return jsonify(active_modules)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)