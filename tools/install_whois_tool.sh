#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${WHOIS_VENV_DIR:-$HOME/.cache/dnsgeeo-whois-venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "error: $PYTHON_BIN not found in PATH" >&2
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtualenv at $VENV_DIR"
  if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
    echo "error: failed to create venv. On Debian/Ubuntu, install python3-venv." >&2
    exit 1
  fi
fi

echo "Installing python dependencies from tools/requirements.txt..."
"$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
"$VENV_DIR/bin/pip" install -r "$(dirname "$0")/requirements.txt" >/dev/null

echo "Installed. Use:"
echo "  $VENV_DIR/bin/python tools/whois_rdap.py --list \"example.com\" --pretty"
