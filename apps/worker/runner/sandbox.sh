#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${1:-}"
PAYLOAD="${2:-}"

if [ -z "$TARGET_URL" ]; then
  echo "Usage: sandbox.sh <target-url> [payload]"
  exit 1
fi

echo "[Worker] Executing isolated probe against ${TARGET_URL}..."
curl -s -i "${TARGET_URL}"
