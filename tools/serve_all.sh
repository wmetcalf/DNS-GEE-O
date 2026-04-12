#!/bin/sh
set -eu

API_HOST="${DNSGEEO_API_HOST:-0.0.0.0}"
API_PORT="${DNSGEEO_API_PORT:-8080}"
MCP_HOST="${DNSGEEO_MCP_HOST:-0.0.0.0}"
MCP_PORT="${DNSGEEO_MCP_PORT:-9090}"
DATA_REFRESH_HOURS="${DNSGEEO_DATA_REFRESH_HOURS:-24}"

# Initial data fetch (force download of missing files)
if [ "${DNSGEEO_SKIP_DATA_REFRESH:-0}" != "1" ]; then
  DNSGEEO_DATA_FORCE_REFRESH=1 python /app/tools/data_refresh.py || echo "warning: initial data refresh failed; continuing" >&2
fi

python -m uvicorn tools.api_server:app --host "$API_HOST" --port "$API_PORT" &
API_PID=$!

python /app/tools/mcp_server.py --host "$MCP_HOST" --port "$MCP_PORT" &
MCP_PID=$!

# Background data refresh loop
if [ "$DATA_REFRESH_HOURS" -gt 0 ] 2>/dev/null; then
  REFRESH_SECONDS=$((DATA_REFRESH_HOURS * 3600))
  (
    while true; do
      sleep "$REFRESH_SECONDS"
      python /app/tools/data_refresh.py 2>&1 | while IFS= read -r line; do echo "[data-refresh] $line"; done >&2
    done
  ) &
  REFRESH_PID=$!
fi

cleanup() {
  kill "$API_PID" "$MCP_PID" 2>/dev/null || true
  [ -n "${REFRESH_PID:-}" ] && kill "$REFRESH_PID" 2>/dev/null || true
}

trap cleanup INT TERM EXIT

while kill -0 "$API_PID" 2>/dev/null && kill -0 "$MCP_PID" 2>/dev/null; do
  sleep 1
done

cleanup
exit 1
