"""Exercise the OAuth-key selection block from the sandbox workflow itself."""

import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/start-sandbox.yml"
BLOCK_START = '          if [[ -z "${MCP_OAUTH_TOKEN_SECRET:-}" ]]; then'
BLOCK_END = '          if [[ "$IMAGE" == "source" ]]; then'
LABEL = b"coding-tools-mcp/oauth-token-secret/v1"
STABLE_TOKEN = "C" * 64


def _oauth_key_setup_script() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    before, marker, remainder = text.partition(BLOCK_START)
    if not marker:
        raise AssertionError("OAuth key selection missing from start-sandbox workflow")
    block, marker, _ = remainder.partition(BLOCK_END)
    if not marker:
        raise AssertionError("OAuth key selection block not terminated")
    lines = (BLOCK_START + block).splitlines()
    if not all(line.startswith("          ") or not line for line in lines):
        raise AssertionError("Unexpected YAML block indentation")
    return "\n".join(line[10:] if line else "" for line in lines)


def _run(token: str, explicit: str = "") -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "MCP_AUTH_TOKEN_SECRET": token,
        "MCP_OAUTH_TOKEN_SECRET": explicit,
    }
    return subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail"],
        input=_oauth_key_setup_script(),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


class WorkflowOAuthSecretTests(unittest.TestCase):
    def test_existing_bearer_secret_yields_stable_domain_separated_oauth_key(self):
        expected = hmac.new(
            STABLE_TOKEN.encode(), LABEL, hashlib.sha256,
        ).hexdigest()
        first = _run(STABLE_TOKEN)
        second = _run(STABLE_TOKEN)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout.strip(), f"::add-mask::{expected}")
        self.assertEqual(first.stdout, second.stdout)
        self.assertNotEqual(expected, hashlib.sha256(STABLE_TOKEN.encode()).hexdigest())

    def test_dedicated_oauth_secret_takes_precedence(self):
        override = "a1" * 32
        result = _run(STABLE_TOKEN, explicit=override)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), f"::add-mask::{override}")

    def test_without_a_stable_secret_fails_closed(self):
        result = _run("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stable signing key", result.stderr)

    def test_short_bearer_secret_is_rejected(self):
        result = _run("short")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("at least 32 characters", result.stderr)


if __name__ == "__main__":
    unittest.main()
