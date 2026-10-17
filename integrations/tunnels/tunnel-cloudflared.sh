#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/tunnel-common.sh"

if [[ -n "${TUNNEL_TOKEN:-}" && -n "${TUNNEL_TOKEN_FILE:-}" ]]; then
  echo "Choose either TUNNEL_TOKEN or TUNNEL_TOKEN_FILE, not both." >&2
  exit 2
fi

tunnel_setup cloudflared "cloudflared" "cloudflared-host" "${1:-}"

if [[ -n "${TUNNEL_TOKEN:-}" || -n "${TUNNEL_TOKEN_FILE:-}" ]]; then
  echo "Using a named Cloudflare Tunnel. Configure its public hostname to route to http://127.0.0.1:$PORT."
  if [[ -z "${CODING_TOOLS_MCP_SERVER_URL:-}" ]]; then
    echo "Tip: set CODING_TOOLS_MCP_SERVER_URL to your stable HTTPS origin (without /mcp)." >&2
  fi
  # cloudflared reads TUNNEL_TOKEN or TUNNEL_TOKEN_FILE from the environment.
  # Do not pass the token on the command line, where process listings can show it.
  cloudflared tunnel run
else
  cloudflared tunnel --url "http://127.0.0.1:$PORT"
fi
