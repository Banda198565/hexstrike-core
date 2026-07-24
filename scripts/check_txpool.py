#!/usr/bin/env python3
"""Check Geth txpool for hot wallet"""
import requests
import json

geth = "http://51.222.42.220:8545"

def rpc(method, params=None):
    if params is None:
        params = []
    r = requests.post(geth, json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1}, timeout=10)
    return r.json()

txpool = rpc("txpool_content")
pending = txpool.get("result", {}).get("pending", {})
queued = txpool.get("result", {}).get("queued", {})

print(f"Pending senders: {len(pending)}")
print(f"Queued senders: {len(queued)}")

hot = "0x4943F5E7F4e450d48Ae82026163ecDe8A52C53dA".lower()
found = False

for addr, txs in pending.items():
    if addr.lower() == hot:
        found = True
        print(f"\n=== HOT WALLET PENDING ===")
        for nonce, tx in txs.items():
            val = int(tx.get("value", "0x0"), 16) / 10**18
            to = tx.get("to", "?")
            inp = tx.get("input", "0x")[:60]
            print(f"  Nonce: {nonce} -> {to} value={val:.6f}")
            print(f"  Input: {inp}")

for addr, txs in queued.items():
    if addr.lower() == hot:
        found = True
        print(f"\n=== HOT WALLET QUEUED ===")
        for nonce, tx in txs.items():
            print(f"  Nonce: {nonce} -> {tx.get('to')}")

if not found:
    print("Hot wallet not in txpool")
    print("\nFirst 5 pending senders:")
    for i, (addr, txs) in enumerate(list(pending.items())[:5]):
        for nonce, tx in list(txs.items())[:1]:
            val = int(tx.get("value", "0x0"), 16) / 10**18
            print(f"  [{i}] {addr}: nonce={nonce} -> {tx.get('to')} value={val:.6f}")
