from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "integrations" / "tunnels" / "tunnel-cloudflared.sh"


@unittest.skipUnless(os.name == "posix", "Bash tunnel launcher is POSIX-specific")
class CloudflaredTunnelLauncherTests(unittest.TestCase):
    def run_launcher(self, *, token: str = "", token_file: bool = False) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fake_cloudflared = base / "cloudflared"
            capture = base / "args.txt"
            fake_cloudflared.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_TUNNEL_CAPTURE"\n', encoding="utf-8"
            )
            fake_cloudflared.chmod(0o755)
            env = os.environ.copy()
            env.pop("TUNNEL_TOKEN", None)
            env.pop("TUNNEL_TOKEN_FILE", None)
            env.update(
                {
                    "PATH": f"{base}:{env.get('PATH', '')}",
                    "TEST_TUNNEL_CAPTURE": str(capture),
                    "CODING_TOOLS_MCP_SERVER_BIN": "/bin/true",
                    "CODING_TOOLS_MCP_AUTH_MODE": "bearer",
                    "CODING_TOOLS_MCP_AUTH_TOKEN": "test-bearer-token",
                    "CODING_TOOLS_MCP_SERVER_URL": "https://mcp.example.com",
                }
            )
            if token:
                env["TUNNEL_TOKEN"] = token
            if token_file:
                secret_file = base / "private-token.txt"
                secret_file.write_text("secret", encoding="utf-8")
                secret_file.chmod(0o600)
                env["TUNNEL_TOKEN_FILE"] = str(secret_file)
            result = subprocess.run(
                ["bash", str(LAUNCHER)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            return result, capture.read_text(encoding="utf-8").splitlines() if capture.exists() else []

    def test_default_quick_tunnel_stays_unchanged(self) -> None:
        result, args = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args, ["tunnel", "--url", "http://127.0.0.1:8765"])

    def test_named_tunnel_reads_token_from_environment(self) -> None:
        result, args = self.run_launcher(token="do-not-print-me")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args, ["tunnel", "run"])
        self.assertNotIn("do-not-print-me", result.stdout + result.stderr)

    def test_named_tunnel_accepts_token_file(self) -> None:
        result, args = self.run_launcher(token_file=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args, ["tunnel", "run"])

    def test_conflicting_token_sources_fail_closed(self) -> None:
        result, args = self.run_launcher(token="one", token_file=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not both", result.stderr)
        self.assertEqual(args, [])


if __name__ == "__main__":
    unittest.main()
