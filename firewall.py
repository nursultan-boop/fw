import subprocess
import json
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
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

def toggle_module(module_name):
    module_path = os.path.join(os.path.dirname(__file__), 'modules', f'{module_name}.py')
    if not os.path.exists(module_path):
        return {"success": False, "error": "Module not found"}
    
    module = __import__(f'modules.{module_name}', fromlist=[''])
    if getattr(module, 'enabled', False):
        module.disable_module()
        module.enabled = False
    else:
        module.enable_module()
        module.enabled = True
    return {"success": True}
