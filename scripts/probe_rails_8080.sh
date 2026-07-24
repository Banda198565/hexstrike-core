#!/bin/sh
# Probe port 8080 on Rails container
for path in /health /status / /config/master.key /master.key /.env /sidekiq /info /proc; do
  result=$(wget -q -T 2 -O - "http://172.19.0.6:8080${path}" 2>&1 | head -c 80)
  echo "${path}: ${result}"
done
