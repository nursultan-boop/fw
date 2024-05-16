# modules/example_module.py

enabled = False

def enable():
    global enabled
    enabled = True
    print("Example module enabled")

def disable():
    global enabled
    enabled = False
    print("Example module disabled")
