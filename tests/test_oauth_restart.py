"""Regression tests for OAuth dynamic client registrations across server restarts."""

import unittest

from coding_tools_mcp.oauth import (
    OAuthClientRegistry,
    OAuthConfig,
    create_access_token,
    validate_access_token,
)


KEY = bytes.fromhex("82" * 32)
OTHER_KEY = bytes.fromhex("93" * 32)
REDIRECT = "https://chatgpt.com/connector/oauth/callback"
SERVER = "https://mcp.example.com"


class RestartSafeOAuthClientsTests(unittest.TestCase):
    def test_public_client_survives_restart_with_same_key(self):
        first = OAuthClientRegistry(signing_key=KEY)
        registration = first.register({
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
            "client_name": "ChatGPT",
        })
        client_id = registration["client_id"]
        self.assertTrue(client_id.startswith("ctm1."))
        self.assertIsNotNone(first.get(client_id))

        restarted = OAuthClientRegistry(signing_key=KEY)
        client = restarted.get(client_id)
        self.assertIsNotNone(client)
        self.assertEqual(client.client_name, "ChatGPT")
        self.assertEqual(client.issued_at, registration["client_id_issued_at"])
        self.assertTrue(restarted.accepts_redirect(client_id, REDIRECT))
        self.assertFalse(restarted.accepts_redirect(client_id, "https://evil.example/callback"))
        self.assertTrue(restarted.authenticates(client_id, "", "none"))
        self.assertFalse(restarted.authenticates(client_id, "unexpected", "none"))

    def test_confidential_client_secret_and_method_survive_restart(self):
        registry = OAuthClientRegistry(signing_key=KEY)
        response = registry.register({
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "client_secret_basic",
        })
        self.assertIn("client_secret", response)
        second = OAuthClientRegistry(signing_key=KEY)
        self.assertTrue(second.authenticates(
            response["client_id"], response["client_secret"], "client_secret_basic",
        ))
        self.assertFalse(second.authenticates(
            response["client_id"], "incorrect", "client_secret_basic",
        ))
        self.assertFalse(second.authenticates(
            response["client_id"], response["client_secret"], "client_secret_post",
        ))

    def test_modified_id_and_wrong_signing_key_are_rejected(self):
        source = OAuthClientRegistry(signing_key=KEY)
        registration = source.register({"redirect_uris": [REDIRECT]})
        original = registration["client_id"]
        tampered = original[:-2] + ("B" if original[-2] != "B" else "C") + original[-1]
        registry = OAuthClientRegistry(signing_key=KEY)
        self.assertIsNone(registry.get(tampered))
        self.assertIsNone(OAuthClientRegistry(signing_key=OTHER_KEY).get(original))
        self.assertIsNone(registry.get("ctm1.not_valid.signature"))
        self.assertIsNone(registry.get("ctm1." + "a" * 8192 + ".sig"))

    def test_original_registration_mode_is_unchanged_without_stable_key(self):
        registry = OAuthClientRegistry()
        registration = registry.register({"redirect_uris": [REDIRECT]})
        self.assertIsNotNone(registry.get(registration["client_id"]))
        self.assertIsNone(OAuthClientRegistry().get(registration["client_id"]))

    def test_access_token_can_be_validated_after_restart(self):
        registry = OAuthClientRegistry(signing_key=KEY)
        client_id = registry.register({"redirect_uris": [REDIRECT]})["client_id"]
        before = OAuthConfig(
            password="password", server_url=SERVER, token_secret=KEY, registry=registry,
        )
        token = create_access_token(before, SERVER, client_id=client_id)
        restarted = OAuthConfig(
            password="password", server_url=SERVER, token_secret=KEY,
            registry=OAuthClientRegistry(signing_key=KEY),
        )
        self.assertTrue(validate_access_token(token, restarted, SERVER))
        self.assertFalse(validate_access_token(token, restarted, "https://wrong.example"))
        self.assertFalse(validate_access_token(
            token,
            OAuthConfig(
                password="password", server_url=SERVER, token_secret=OTHER_KEY,
                registry=OAuthClientRegistry(signing_key=OTHER_KEY),
            ),
            SERVER,
        ))

    def test_short_signing_key_is_rejected(self):
        with self.assertRaises(ValueError):
            OAuthClientRegistry(signing_key=b"short")


if __name__ == "__main__":
    unittest.main()
