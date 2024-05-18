from flask import Flask, render_template, request, redirect, url_for, jsonify
import requests

app = Flask(__name__)

FIREWALL_API = 'http://localhost:5000'

@app.route('/')
def index():
    devices = requests.get(f'{FIREWALL_API}/devices').json()
    groups = requests.get(f'{FIREWALL_API}/groups').json()
    modules = requests.get(f'{FIREWALL_API}/modules').json()
    return render_template('index.html', devices=devices, groups=groups, modules=modules)

@app.route('/group/<group_name>')
def group(group_name):
    groups = requests.get(f'{FIREWALL_API}/groups').json()
    devices = requests.get(f'{FIREWALL_API}/devices').json()
    if group_name in groups:
        return render_template('group.html', group_name=group_name, group=groups[group_name], devices=devices)
    return redirect(url_for('index'))

@app.route('/add_group', methods=['POST'])
def add_group():
    group_name = request.form.get('group_name')
    if group_name:
        response = requests.post(f'{FIREWALL_API}/groups', json={'name': group_name})
        if response.status_code == 201:
            return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/add_device_to_group', methods=['POST'])
def add_device_to_group():
    group_name = request.form.get('group_name')
    device_name = request.form.get('device_name')
    if group_name and device_name:
        response = requests.post(f'{FIREWALL_API}/groups/assign', json={'group': group_name, 'device': device_name})
        if response.status_code == 200:
            return redirect(url_for('group', group_name=group_name))
    return redirect(url_for('index'))

@app.route('/remove_device_from_group', methods=['POST'])
def remove_device_from_group():
    group_name = request.form.get('group_name')
    device_name = request.form.get('device_name')
    if group_name and device_name:
        response = requests.post(f'{FIREWALL_API}/groups/remove_device', json={'group': group_name, 'device': device_name})
        if response.status_code == 200:
            return redirect(url_for('group', group_name=group_name))
    return redirect(url_for('index'))

@app.route('/add_rule', methods=['POST'])
def add_rule():
    group_name = request.form.get('group_name')
    rule = request.form.get('rule')
    if group_name and rule:
        response = requests.post(f'{FIREWALL_API}/rules', json={'group': group_name, 'rule': rule})
        if response.status_code == 201:
            return redirect(url_for('group', group_name=group_name))
    return redirect(url_for('index'))

@app.route('/remove_rule', methods=['POST'])
def remove_rule():
    group_name = request.form.get('group_name')
    rule = request.form.get('rule')
    if group_name and rule:
        response = requests.delete(f'{FIREWALL_API}/rules', json={'group': group_name, 'rule': rule})
        if response.status_code == 200:
            return redirect(url_for('group', group_name=group_name))
    return redirect(url_for('index'))

@app.route('/toggle_module', methods=['POST'])
def toggle_module():
    module_name = request.form.get('module_name')
    action = request.form.get('action')
    if module_name and action:
        response = requests.post(f'{FIREWALL_API}/modules', json={'module': module_name, 'action': action})
        if response.status_code == 200:
            return redirect(url_for('index'))
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
