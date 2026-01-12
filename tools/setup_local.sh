#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: tools/setup_local.sh [options]

Options:
  --skip-whois          Skip installing WHOIS helper deps
  --skip-build          Skip building the Go CLI
  --skip-db             Skip GeoLite2 download (sets MAXMIND_LICENSE_KEY="")
  --python-bin PATH     Python binary for WHOIS helper (default: python3)
  --venv-dir PATH       Virtualenv directory for WHOIS helper
  -h, --help            Show this help
EOF
}

SKIP_WHOIS=0
SKIP_BUILD=0
SKIP_DB=0
PYTHON_BIN=""
VENV_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-whois) SKIP_WHOIS=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --skip-db) SKIP_DB=1 ;;
    --python-bin)
      shift
      PYTHON_BIN="${1:-}"
      ;;
    --venv-dir)
      shift
      VENV_DIR="${1:-}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [ "$SKIP_BUILD" -eq 0 ]; then
  echo "[1/2] Building CLI and optional GeoIP DBs..."
  if [ "$SKIP_DB" -eq 1 ]; then
    MAXMIND_LICENSE_KEY="" "$ROOT/install.sh"
  else
    "$ROOT/install.sh"
  fi
else
  echo "[1/2] Skipping CLI build."
fi

if [ "$SKIP_WHOIS" -eq 0 ]; then
  echo "[2/2] Installing WHOIS/RDAP helper deps..."
  if [ -n "$PYTHON_BIN" ]; then
    export PYTHON_BIN
  fi
  if [ -n "$VENV_DIR" ]; then
    export WHOIS_VENV_DIR="$VENV_DIR"
  fi
  "$ROOT/tools/install_whois_tool.sh"
else
  echo "[2/2] Skipping WHOIS helper setup."
fi

echo "Done."
echo "Binary: $ROOT/bin/dnsgeeo"
if [ "$SKIP_WHOIS" -eq 0 ]; then
  echo "WHOIS helper: ${WHOIS_VENV_DIR:-$HOME/.cache/dnsgeeo-whois-venv}/bin/python"
fi
