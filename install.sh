#!/usr/bin/env bash
set -euo pipefail

REPO="lorikeetsecurity/lory"
TARGET_DIR="/usr/local/bin"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

BIN_URL="https://github.com/${REPO}/releases/latest/download/lory-${OS}-${ARCH}"

echo "🦜 Installing Lorikeet Lory (${OS}/${ARCH})..."
TMP_FILE="$(mktemp)"
curl -fsSL "$BIN_URL" -o "$TMP_FILE" || {
  echo "Downloading prebuilt binary failed; compiling locally from source..."
  if command -v go >/dev/null 2>&1; then
    go build -o "$TMP_FILE" apps/cli/main.go
  else
    echo "Error: Neither prebuilt binary nor Go compiler found."
    exit 1
  fi
}

chmod +x "$TMP_FILE"

if [ -w "$TARGET_DIR" ]; then
  mv "$TMP_FILE" "${TARGET_DIR}/lory"
else
  sudo mv "$TMP_FILE" "${TARGET_DIR}/lory"
fi

echo "✔ Successfully installed lory to ${TARGET_DIR}/lory"
lory --help
