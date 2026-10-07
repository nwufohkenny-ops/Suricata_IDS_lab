#!/usr/bin/env bash
set -euo pipefail

echo "== Suricata build info =="
suricata --build-info | head -n 12 || true

echo
echo "== Interfaces =="
ip -br addr

echo
echo "== Routes =="
ip route

echo
echo "== Listener on TCP/9999 =="
ss -lntp 2>/dev/null | grep ':9999' || echo "No TCP/9999 listener detected."

echo
echo "== Custom rule =="
sudo grep -n "LOCAL LAB Netcat" /etc/suricata/rules/local.rules || true

echo
echo "== Configuration test =="
sudo suricata -T -c /etc/suricata/suricata.yaml

echo
echo "[+] Basic verification complete."
