#!/usr/bin/env bash
set -euo pipefail

SURICATA_IP="${1:-<SURICATA_IP>}"
PORT="${2:-9999}"
MARKER="${3:-SURICATA-LAB-TEST}"

if [[ "$SURICATA_IP" == "<SURICATA_IP>" ]]; then
  echo "Usage: $0 <SURICATA_IP> [PORT] [MARKER]"
  exit 1
fi

echo "[+] Sending authorized lab marker to ${SURICATA_IP}:${PORT}"
printf '%s\n' "$MARKER" | nc -nv -w 3 "$SURICATA_IP" "$PORT"
echo "[+] Traffic generation complete."
