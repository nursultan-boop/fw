# admin_panel/app.py
from flask import Flask, render_template, request, redirect, url_for
import requests

app = Flask(__name__)
API_URL = 'http://localhost:5000'

@app.route('/')
def index():
    devices = requests.get(f'{API_URL}/devices').json()
    groups = requests.get(f'{API_URL}/groups').json()
    rules = requests.get(f'{API_URL}/rules').json()
    modules = requests.get(f'{API_URL}/modules').json()
    return render_template('index.html', devices=devices, groups=groups, rules=rules, modules=modules)

@app.route('/add_group', methods=['POST'])
def add_group():
    group = {'name': request.form['name']}
    requests.post(f'{API_URL}/groups', json=group)
    return redirect(url_for('index'))

@app.route('/edit_group', methods=['POST'])
def edit_group():
    old_name = request.form['old_name']
    new_name = request.form['new_name']
    group = {'old_name': old_name, 'new_name': new_name}
    requests.put(f'{API_URL}/groups', json=group)
    return redirect(url_for('index'))

@app.route('/delete_group', methods=['POST'])
def delete_group():
    group = {'name': request.form['name']}
    requests.delete(f'{API_URL}/groups', json=group)
    return redirect(url_for('index'))

@app.route('/assign_device', methods=['POST'])
def assign_device():
    group = request.form['group']
    device = request.form['device']
    assignment = {'group': group, 'device': device}
    requests.post(f'{API_URL}/groups/assign', json=assignment)
    return redirect(url_for('index'))

@app.route('/add_rule', methods=['POST'])
def add_rule():
    rule = {
        'group': request.form['group'],
        'rule': request.form['rule']
    }
    requests.post(f'{API_URL}/rules', json=rule)
    return redirect(url_for('index'))

@app.route('/manage_module', methods=['POST'])
def manage_module():
    module_name = request.form['module']
    action = request.form['action']
    module = {'module': module_name, 'action': action}
    requests.post(f'{API_URL}/modules', json=module)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
