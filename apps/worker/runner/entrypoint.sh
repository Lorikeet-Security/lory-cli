#!/usr/bin/env bash
set -euo pipefail

echo "🦜 Lorikeet Lory Ephemeral Worker Sandbox"
echo "Target Workspace: ${PWD}"

if [ "$#" -eq 0 ]; then
  exec /bin/bash
else
  exec "$@"
fi
