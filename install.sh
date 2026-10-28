#!/usr/bin/env bash
set -euo pipefail

REPO="Lorikeet-Security/lory-cli"
TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"

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

if curl -fsSL "$BIN_URL" -o "$TMP_FILE" 2>/dev/null && [ -s "$TMP_FILE" ]; then
  chmod +x "$TMP_FILE"
elif command -v go >/dev/null 2>&1; then
  echo "Prebuilt binary not found on GitHub release; building with Go..."
  if go install "github.com/${REPO}@latest" 2>/dev/null; then
    GOBIN="$(go env GOPATH)/bin"
    if [ -f "${GOBIN}/lory-cli" ]; then
      cp "${GOBIN}/lory-cli" "$TMP_FILE"
    elif [ -f "${GOBIN}/lory" ]; then
      cp "${GOBIN}/lory" "$TMP_FILE"
    fi
  fi

  if [ ! -s "$TMP_FILE" ]; then
    TMP_DIR="$(mktemp -d)"
    git clone --depth 1 "https://github.com/${REPO}.git" "$TMP_DIR"
    (cd "$TMP_DIR" && go build -o "$TMP_FILE" apps/cli/main.go)
    rm -rf "$TMP_DIR"
  fi
  chmod +x "$TMP_FILE"
else
  echo "Error: Neither prebuilt binary nor Go compiler found."
  echo "Please install Go (https://golang.org) or visit https://github.com/${REPO}/releases."
  rm -f "$TMP_FILE"
  exit 1
fi

if [ -w "$TARGET_DIR" ]; then
  mv "$TMP_FILE" "${TARGET_DIR}/lory"
else
  sudo mv "$TMP_FILE" "${TARGET_DIR}/lory"
fi

echo "✔ Successfully installed lory to ${TARGET_DIR}/lory"
lory --help || true
