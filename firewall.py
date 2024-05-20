import subprocess

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
