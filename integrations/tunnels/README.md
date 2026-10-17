# Tunnel integrations

These scripts expose a local coding-tools MCP server through a supported tunnel provider.

They are user-facing runtime integrations rather than repository-maintenance scripts, so they live outside `scripts/`.

```bash
CODING_TOOLS_MCP_AUTH_MODE=bearer ./integrations/tunnels/tunnel.sh cloudflared /path/to/repo
```

Supported providers are `cloudflared`, `ngrok`, and `devtunnel`.

For a stable Cloudflare hostname, the launcher supports remotely-managed named
tunnels using `TUNNEL_TOKEN` or `TUNNEL_TOKEN_FILE`; without them, it uses a
temporary Quick Tunnel. For setup and security guidance, see
[Remote MCP: stable Cloudflare tunnel](../../docs/remote-mcp.md#stable-cloudflare-tunnel).
