#!/usr/bin/env python3
"""Try different org header names for Lago GraphQL API"""
import urllib.request
import urllib.error
import json

TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhNzQxNzZhNy1kMDBhLTRjZDQtYmVlOC1kYmUyYTg3OTFlMjMiLCJleHAiOjE3ODQ2NzQ0MjgsImxvZ2luX21ldGhvZCI6ImVtYWlsX3Bhc3N3b3JkIn0.6pox0onHuwi8U0U04B1bANXfDskxImunDNOtl8kOZa0"
ORG_ID = "655f020d-3950-477f-bbcb-9d4ae44fa25d"
QUERY = '{"query":"{ organization { id name } }"}'

headers_to_try = [
    "X-Lago-Organization-Id",
    "X-Organization-Id",
    "X-Organization",
    "Lago-Organization",
    "x-organization-id",
    "x-lago-organization-id",
    "organization-id",
    "Organization-Id",
    "Organization",
    "Lago-Organization-Id",
    "lago-organization-id",
    "X-Lago-Org-Id",
    "X-Org-Id",
]

for header_name in headers_to_try:
    req = urllib.request.Request(
        "http://38.107.234.149:3000/graphql",
        data=QUERY.encode(),
        headers={
            "Authorization": "Bearer " + TOKEN,
            "Content-Type": "application/json",
            header_name: ORG_ID,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
            data = json.loads(body)
            if "data" in data and data["data"] and data["data"]["organization"]:
                print("[{}] SUCCESS: {}".format(header_name, body[:200]))
            else:
                errors = data.get("errors", [{}])
                msg = errors[0].get("message", "?") if errors else "?"
                print("[{}] FAIL: {}".format(header_name, msg))
    except urllib.error.HTTPError as e:
        print("[{}] HTTP {}".format(header_name, e.code))
    except Exception as e:
        print("[{}] ERROR: {}".format(header_name, e))

print("\nDone")
