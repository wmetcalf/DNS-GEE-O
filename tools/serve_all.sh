#!/bin/sh
set -eu

API_HOST="${DNSGEEO_API_HOST:-0.0.0.0}"
API_PORT="${DNSGEEO_API_PORT:-8080}"
MCP_HOST="${DNSGEEO_MCP_HOST:-0.0.0.0}"
MCP_PORT="${DNSGEEO_MCP_PORT:-9090}"

if [ "${DNSGEEO_SKIP_GEOIP_DOWNLOAD:-0}" != "1" ]; then
  python /app/tools/geoip_fetch.py || echo "warning: GeoLite2 download failed; continuing without DBs" >&2
fi

LOLFSAAS_DB="${DNSGEEO_LOLFSAAS_DB:-/app/data/lolfsaas.json}"
if [ ! -f "$LOLFSAAS_DB" ] || [ "${DNSGEEO_LOLFSAAS_FORCE_DOWNLOAD:-0}" = "1" ]; then
  curl -sSfL "https://raw.githubusercontent.com/lolfsaas/lolfsaas.github.io/main/data.json" -o "$LOLFSAAS_DB" \
    || echo "warning: LOLFSaaS download failed; continuing without it" >&2
fi

python -m uvicorn tools.api_server:app --host "$API_HOST" --port "$API_PORT" &
API_PID=$!

python /app/tools/mcp_server.py --host "$MCP_HOST" --port "$MCP_PORT" &
MCP_PID=$!

cleanup() {
  kill "$API_PID" "$MCP_PID" 2>/dev/null || true
}

trap cleanup INT TERM EXIT

while kill -0 "$API_PID" 2>/dev/null && kill -0 "$MCP_PID" 2>/dev/null; do
  sleep 1
done

cleanup
exit 1
