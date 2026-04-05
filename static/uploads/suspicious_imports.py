import os
import subprocess
import socket
import requests
import base64

# These are just comments - NO actual malicious code runs
# This file is completely safe and only contains suspicious PATTERNS

def fake_command():
    # These strings look like commands but are just commented out
    # os.system("cmd.exe /c del")
    # subprocess.Popen("powershell")
    
    encoded = "dGhpcyBpcyBhIHRlc3Q="
    decoded = base64.b64decode(encoded)
    return decoded

print("This is a SAFE test file with suspicious patterns only")