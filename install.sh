#!/usr/bin/env bash
set -euo pipefail

# Simple installer for dnsgeeo
# - Builds the CLI binary into ./bin/dnsgeeo (or specified bin dir)
# - Downloads GeoLite2 City & ASN databases into the data dir if MAXMIND_LICENSE_KEY is set
# - Optionally writes a config file so defaults include Quad9, GeoIP, and WHOIS

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$ROOT/bin"
DATA_DIR="$ROOT/data"
TMP_DIR="$ROOT/.tmp"
CONFIG_PATH=""
WRITE_CONFIG=1
INSTALL_WHOIS=1
INSTALL_MODE="local"
WHOIS_VENV_DIR="${WHOIS_VENV_DIR:-}"

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --bin-dir PATH       Install binary to PATH
  --data-dir PATH      Store GeoIP databases in PATH
  --config-path PATH   Write config to PATH (default: ~/.config/dnsgeeo/dnsgeeo.conf)
  --user-bin           Install to ~/.local/bin and ~/.local/share/dnsgeeo
  --global-bin         Install to /usr/local/bin and /usr/local/share/dnsgeeo
  --no-config          Skip writing config file
  --skip-whois         Skip installing Python WHOIS dependencies
  -h, --help           Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --bin-dir)
      shift
      BIN_DIR="${1:-}"
      ;;
    --data-dir)
      shift
      DATA_DIR="${1:-}"
      ;;
    --config-path)
      shift
      CONFIG_PATH="${1:-}"
      ;;
    --user-bin)
      BIN_DIR="${HOME}/.local/bin"
      DATA_DIR="${HOME}/.local/share/dnsgeeo"
      INSTALL_MODE="user"
      ;;
    --global-bin)
      BIN_DIR="/usr/local/bin"
      DATA_DIR="/usr/local/share/dnsgeeo"
      INSTALL_MODE="global"
      ;;
    --no-config)
      WRITE_CONFIG=0
      ;;
    --skip-whois)
      INSTALL_WHOIS=0
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

if [ -n "${DNSGEEO_TMP_DIR:-}" ]; then
  TMP_DIR="$DNSGEEO_TMP_DIR"
elif [ -n "${DNSGEO_TMP_DIR:-}" ]; then
  TMP_DIR="$DNSGEO_TMP_DIR"
fi

if [ -z "$CONFIG_PATH" ] && [ "$WRITE_CONFIG" -eq 1 ]; then
  if [ "$INSTALL_MODE" = "global" ]; then
    CONFIG_PATH="/usr/local/etc/dnsgeeo.conf"
  else
    CONFIG_PATH="${HOME}/.config/dnsgeeo/dnsgeeo.conf"
  fi
fi

mkdir -p "$BIN_DIR" "$DATA_DIR"
if ! mkdir -p "$TMP_DIR" 2>/dev/null; then
  TMP_DIR="$(mktemp -d -t dnsgeeo-tmp.XXXXXX)"
  echo "warning: TMP_DIR not writable; using $TMP_DIR"
fi

echo "[1/5] Checking prerequisites..."
command -v go >/dev/null 2>&1 || { echo "Go is required (>=1.23). Install Go and re-run."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required."; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required."; exit 1; }

echo "[2/5] Tidying modules and building CLI..."
pushd "$ROOT" >/dev/null
go mod tidy
GO111MODULE=on go build -o "$TMP_DIR/dnsgeeo" ./cmd/dnsgeeo
popd >/dev/null
install -m 0755 "$TMP_DIR/dnsgeeo" "$BIN_DIR/dnsgeeo"
echo "Built: $BIN_DIR/dnsgeeo"

echo "[3/5] Attempting to download GeoIP databases (optional)..."
if [[ -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo "MAXMIND_LICENSE_KEY detected; downloading GeoLite2 City & ASN..."
  CITY_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
  ASN_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

  CITY_TGZ="$TMP_DIR/geolite2-city.tgz"
  ASN_TGZ="$TMP_DIR/geolite2-asn.tgz"

  echo "Downloading City DB..."
  curl -fsSL "$CITY_URL" -o "$CITY_TGZ"
  echo "Downloading ASN DB..."
  curl -fsSL "$ASN_URL" -o "$ASN_TGZ"

  echo "Extracting..."
  rm -rf "$TMP_DIR/city" "$TMP_DIR/asn"
  mkdir -p "$TMP_DIR/city" "$TMP_DIR/asn"
  tar -xzf "$CITY_TGZ" -C "$TMP_DIR/city"
  tar -xzf "$ASN_TGZ" -C "$TMP_DIR/asn"

  # Find the .mmdb files and move them into ./data
  CITY_MMDB="$(find "$TMP_DIR/city" -type f -name 'GeoLite2-City.mmdb' | head -n 1 || true)"
  ASN_MMDB="$(find "$TMP_DIR/asn" -type f -name 'GeoLite2-ASN.mmdb' | head -n 1 || true)"

  if [[ -f "$CITY_MMDB" ]]; then
    cp "$CITY_MMDB" "$DATA_DIR/GeoLite2-City.mmdb"
    echo "City DB -> $DATA_DIR/GeoLite2-City.mmdb"
  else
    echo "City DB not found in archive (download may have failed)."
  fi

  if [[ -f "$ASN_MMDB" ]]; then
    cp "$ASN_MMDB" "$DATA_DIR/GeoLite2-ASN.mmdb"
    echo "ASN DB  -> $DATA_DIR/GeoLite2-ASN.mmdb"
  else
    echo "ASN DB not found in archive (download may have failed)."
  fi
else
  echo "No MAXMIND_LICENSE_KEY env var set; skipping GeoLite2 download."
  echo "You can still use the CLI by pointing to your own MMDBs via --city-db/--asn-db"
  echo "(e.g., DB-IP Lite City .mmdb)."
fi

echo "[4/5] Installing WHOIS tool dependencies (optional)..."
if [ -z "$WHOIS_VENV_DIR" ]; then
  if [ "$INSTALL_MODE" = "global" ]; then
    WHOIS_VENV_DIR="/usr/local/share/dnsgeeo/venv"
  else
    WHOIS_VENV_DIR="$HOME/.cache/dnsgeeo-whois-venv"
  fi
fi
if [ "$INSTALL_WHOIS" -eq 1 ]; then
  WHOIS_VENV_DIR="$WHOIS_VENV_DIR" "$ROOT/tools/install_whois_tool.sh"
else
  echo "Skipping WHOIS dependency install."
fi

echo "[5/5] Writing config (optional)..."
if [ "$WRITE_CONFIG" -eq 1 ]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  WHOIS_TOOL_PATH="$ROOT/tools/whois_rdap.py"
  WHOIS_PYTHON="$WHOIS_VENV_DIR/bin/python"
  WHOIS_ENABLED="true"
  if [ "$INSTALL_WHOIS" -ne 1 ]; then
    WHOIS_PYTHON="python3"
    WHOIS_ENABLED="false"
  fi
  cat >"$CONFIG_PATH" <<EOF
# dnsgeeo default config (generated by install.sh)
dns=8.8.8.8:53,8.8.4.4:53
check-malicious=true
whois=$WHOIS_ENABLED
whois-tool=$WHOIS_TOOL_PATH
whois-python=$WHOIS_PYTHON
whois-timeout-ms=20000
city-db=$DATA_DIR/GeoLite2-City.mmdb
asn-db=$DATA_DIR/GeoLite2-ASN.mmdb
prefer-ipv6=true
EOF
  echo "Wrote config: $CONFIG_PATH"
else
  echo "Skipping config file write."
fi

echo "Done."
echo
echo "Examples:"
echo "  $BIN_DIR/dnsgeeo --pretty example.com"
echo "  $BIN_DIR/dnsgeeo --list \"example.com,openai.com\""
