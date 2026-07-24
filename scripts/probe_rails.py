#!/usr/bin/env python3
"""Probe Rails debug endpoints"""
import urllib.request
import urllib.error

TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhNzQxNzZhNy1kMDBhLTRjZDQtYmVlOC1kYmUyYTg3OTFlMjMiLCJleHAiOjE3ODQ2NzQ0MjgsImxvZ2luX21ldGhvZCI6ImVtYWlsX3Bhc3N3b3JkIn0.6pox0onHuwi8U0U04B1bANXfDskxImunDNOtl8kOZa0"
ORG = "x-lago-organization: 655f020d-3950-477f-bbcb-9d4ae44fa25d"

paths = [
    "/rails/info", "/rails/info/routes", "/rails/info/properties",
    "/rails/info/environment", "/_debug", "/debug", "/console",
    "/dev", "/admin", "/system", "/system/info", "/status",
    "/health", "/rails/db", "/sidekiq", "/rails/mailers",
    "/assets/internal", "/__better_errors", "/rails/console",
    "/api/v1/admin", "/internal"
]

for path in paths:
    req = urllib.request.Request(
        "http://38.107.234.149:3000" + path,
        headers={
            "Authorization": "Bearer " + TOKEN,
            ORG.split(":")[0]: ORG.split(": ")[1],
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            code = resp.getcode()
            body = resp.read(200).decode(errors="replace")
            print("{} -> HTTP {} : {}".format(path, code, body[:80].strip()))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print("{} -> HTTP {}".format(path, e.code))
    except Exception:
        pass

print("\nDone")
