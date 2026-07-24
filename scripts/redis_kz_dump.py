#!/usr/bin/env python3
"""Redis key dump from 38.107.234.149:6379"""
import socket
import time
import re
from collections import Counter

def redis_cmd(cmd, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("38.107.234.149", 6379))
    s.send(cmd.encode() if isinstance(cmd, str) else cmd)
    time.sleep(1)
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


# SCAN all keys
cursor = 0
all_keys = []
while True:
    raw = redis_cmd("SCAN {} COUNT 500\r\n".format(cursor))
    # Parse: *2\r\n$1\r\n0\r\n*N\r\n... bulk strings
    lines = raw.split("\r\n")
    # Find the array of keys
    found_keys = False
    keys_in_chunk = 0
    for line in lines:
        line_s = line.strip()
        if line_s.startswith("*") and not found_keys:
            # Second array in response is the key list
            arr_size = int(line_s[1:])
            if arr_size > 1:
                found_keys = True
                continue
        if found_keys:
            if line_s.startswith("$") or line_s.startswith("*"):
                continue
            if line_s:
                all_keys.append(line_s)

    # Find new cursor from first array element
    cursor_match = re.search(r"\*2\r\n\$\d+\r\n(\d+)", raw)
    if cursor_match:
        new_cursor = int(cursor_match.group(1))
        if new_cursor == 0 or new_cursor == cursor:
            break
        cursor = new_cursor
    else:
        break

    if len(all_keys) > 4000:
        break

print("Total keys: {}".format(len(all_keys)))

# Group by prefix
prefixes = Counter()
for k in all_keys:
    prefix = k.split(":")[0].split("/")[0] if ":" in k or "/" in k else k
    prefixes[prefix] += 1

print("\n=== Key prefixes ===")
for seg, cnt in prefixes.most_common(40):
    print("  {:30s} {}".format(seg, cnt))
