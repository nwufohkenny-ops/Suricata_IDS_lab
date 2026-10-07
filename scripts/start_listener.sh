#!/usr/bin/env bash
set -euo pipefail
PORT="${1:-9999}"
echo "[+] Listening for authorized lab traffic on TCP/${PORT}"
exec nc -lvnp "$PORT"
