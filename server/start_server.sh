#!/usr/bin/env bash
# Start TestMyNIDS Local Resource Server
set -e

PORT="${1:-8080}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Launching TestMyNIDS resource server on port $PORT..."
python3 "$SCRIPT_DIR/app.py" --port "$PORT"
