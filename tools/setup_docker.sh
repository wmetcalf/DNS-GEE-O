#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: tools/setup_docker.sh [options]

Options:
  --build         Build images before starting (default)
  --no-build      Skip image build
  --pull          Pull base images
  --down          Stop and remove containers
  --compose FILE  Use an alternate compose file
  -h, --help      Show this help
EOF
}

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker not found in PATH" >&2
  exit 1
fi

COMPOSE_FILE="$ROOT/docker-compose.yml"
DO_BUILD=1
DO_PULL=0
DO_DOWN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --build) DO_BUILD=1 ;;
    --no-build) DO_BUILD=0 ;;
    --pull) DO_PULL=1 ;;
    --down) DO_DOWN=1 ;;
    --compose)
      shift
      COMPOSE_FILE="${1:-}"
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

if [ "$DO_DOWN" -eq 1 ]; then
  docker compose -f "$COMPOSE_FILE" down
  exit 0
fi

if [ "$DO_PULL" -eq 1 ]; then
  docker compose -f "$COMPOSE_FILE" pull
fi

echo "Building and starting API + MCP + Redis..."
if [ "$DO_BUILD" -eq 1 ]; then
  docker compose -f "$COMPOSE_FILE" up -d --build
else
  docker compose -f "$COMPOSE_FILE" up -d
fi

echo "Done."
echo "API: http://localhost:8080/resolve"
echo "MCP: http://localhost:9091/mcp"
