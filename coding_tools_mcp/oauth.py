from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import jwt


OAUTH_CODE_TTL_SECONDS = 300
OAUTH_TOKEN_TTL_SECONDS = 24 * 60 * 60
OAUTH_MAX_BODY_BYTES = 8_192
OAUTH_GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
# Advertised in AS metadata and used to narrow DCR requests. The token endpoint
# implements authorization_code only — adding an entry here requires a matching
# branch in handle_oauth_token, not just a wider check.
OAUTH_GRANT_TYPES_SUPPORTED = (OAUTH_GRANT_TYPE_AUTHORIZATION_CODE,)
OAUTH_RESPONSE_TYPES_SUPPORTED = ("code",)
MAX_REDIRECT_URIS = 10
MAX_REGISTERED_CLIENTS = 1_024
MAX_PENDING_CODES = 256
SIGNED_CLIENT_ID_PREFIX = "ctm1"
# Limits abuse of self-contained client IDs in authorize URLs and JWT subjects.
MAX_SIGNED_CLIENT_ID_CHARS = 8_192


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    redirect_uris: tuple[str, ...]
    token_endpoint_auth_method: str
    client_name: str | None = None
    secret_digest: str | None = None
    issued_at: int = field(default_factory=lambda: int(time.time()))

    def accepts_redirect(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    def verifies_secret(self, secret: str) -> bool:
        if self.token_endpoint_auth_method == "none":
            return not secret
        if self.secret_digest is None or not secret:
            return False
        return secrets.compare_digest(self.secret_digest, _secret_digest(secret))


class OAuthClientRegistry:
    """Thread-safe RFC 7591 client registry for one server process."""

    def __init__(self, *, signing_key: bytes | None = None) -> None:
        # Without a stable signing key the legacy in-memory registry is retained.
        # With one, DCR client IDs carry authenticated metadata and survive restarts.
        if signing_key is not None and len(signing_key) < 32:
            raise ValueError("OAuth client signing key must be at least 32 bytes")
        self._signing_key = (
            hmac.new(signing_key, b"coding-tools-mcp/oauth-dcr-client/v1", hashlib.sha256).digest()
            if signing_key is not None else None
        )
        self._clients: dict[str, OAuthClient] = {}
        self._lock = threading.Lock()

    def add_preregistered(
        self,
        client_id: str,
        redirect_uris: tuple[str, ...],
        *,
        client_secret: str | None,
    ) -> None:
        redirects = validate_redirect_uris(list(redirect_uris))
        method = "client_secret_post" if client_secret is not None else "none"
        client = OAuthClient(
            client_id=client_id,
            redirect_uris=redirects,
            token_endpoint_auth_method=method,
            secret_digest=_secret_digest(client_secret) if client_secret is not None else None,
        )
        with self._lock:
            self._clients[client_id] = client

    def register(self, metadata: dict[str, Any]) -> dict[str, Any]:
        redirects = validate_redirect_uris(metadata.get("redirect_uris"))
        requested_grant_types = metadata.get("grant_types", list(OAUTH_GRANT_TYPES_SUPPORTED))
        requested_response_types = metadata.get("response_types", list(OAUTH_RESPONSE_TYPES_SUPPORTED))
        if not isinstance(requested_grant_types, list) or not all(
            isinstance(item, str) for item in requested_grant_types
        ):
            raise ValueError("grant_types must be an array of strings")
        grant_types = tuple(item for item in OAUTH_GRANT_TYPES_SUPPORTED if item in requested_grant_types)
        if not grant_types:
            raise ValueError("grant_types must include at least one supported value")
        if not isinstance(requested_response_types, list) or not all(
            isinstance(item, str) for item in requested_response_types
        ):
            raise ValueError("response_types must be an array of strings")
        response_types = tuple(item for item in OAUTH_RESPONSE_TYPES_SUPPORTED if item in requested_response_types)
        if not response_types:
            raise ValueError("response_types must include at least one supported value")
        method = str(metadata.get("token_endpoint_auth_method") or "none")
        if method not in {"none", "client_secret_post", "client_secret_basic"}:
            raise ValueError("unsupported token_endpoint_auth_method")
        with self._lock:
            if len(self._clients) >= MAX_REGISTERED_CLIENTS:
                raise ValueError("dynamic client registration limit reached")
            client_secret = secrets.token_urlsafe(32) if method != "none" else None
            client_name = _optional_text(metadata.get("client_name"), 200)
            digest = _secret_digest(client_secret) if client_secret is not None else None
            issued_at = int(time.time())
            if self._signing_key is None:
                client_id = secrets.token_urlsafe(24)
                while client_id in self._clients:
                    client_id = secrets.token_urlsafe(24)
            else:
                # No database is available on ephemeral GitHub Actions runners.
                # The HMAC authenticates the redirects, auth method and high-entropy
                # client-secret digest, without storing or exposing the secret.
                payload = json.dumps(
                    {
                        "redirect_uris": list(redirects),
                        "token_endpoint_auth_method": method,
                        "client_name": client_name,
                        "secret_digest": digest,
                        "issued_at": issued_at,
                        "nonce": secrets.token_urlsafe(12),
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                signature = hmac.new(self._signing_key, payload, hashlib.sha256).digest()
                client_id = (
                    f"{SIGNED_CLIENT_ID_PREFIX}."
                    f"{_b64url(payload)}.{_b64url(signature)}"
                )
                if len(client_id) > MAX_SIGNED_CLIENT_ID_CHARS:
                    raise ValueError("OAuth client metadata exceeds signed client ID size limit")
            client = OAuthClient(
                client_id=client_id,
                redirect_uris=redirects,
                token_endpoint_auth_method=method,
                client_name=client_name,
                secret_digest=digest,
                issued_at=issued_at,
            )
            if self._signing_key is None:
                self._clients[client_id] = client
        response: dict[str, Any] = {
            "client_id": client.client_id,
            "client_id_issued_at": client.issued_at,
            "redirect_uris": list(client.redirect_uris),
            "grant_types": list(grant_types),
            "response_types": list(response_types),
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
        }
        if client.client_name:
            response["client_name"] = client.client_name
        if client_secret is not None:
            response["client_secret"] = client_secret
            response["client_secret_expires_at"] = 0
        return response

    def get(self, client_id: str) -> OAuthClient | None:
        with self._lock:
            client = self._clients.get(client_id)
        return client if client is not None else self._verify_signed_client(client_id)

    def _verify_signed_client(self, client_id: str) -> OAuthClient | None:
        if (
            self._signing_key is None
            or not isinstance(client_id, str)
            or len(client_id) > MAX_SIGNED_CLIENT_ID_CHARS
        ):
            return None
        parts = client_id.split(".")
        if len(parts) != 3 or parts[0] != SIGNED_CLIENT_ID_PREFIX:
            return None
        try:
            payload = _decode_b64url(parts[1])
            signature = _decode_b64url(parts[2])
            if len(signature) != hashlib.sha256().digest_size:
                return None
            if not hmac.compare_digest(
                hmac.new(self._signing_key, payload, hashlib.sha256).digest(),
                signature,
            ):
                return None
            data = json.loads(payload)
            if not isinstance(data, dict) or set(data) != {
                "redirect_uris", "token_endpoint_auth_method", "client_name",
                "secret_digest", "issued_at", "nonce",
            }:
                return None
            redirects = validate_redirect_uris(data["redirect_uris"])
            method = data["token_endpoint_auth_method"]
            name = data["client_name"]
            digest = data["secret_digest"]
            issued_at = data["issued_at"]
            nonce = data["nonce"]
            if method not in {"none", "client_secret_post", "client_secret_basic"}:
                return None
            if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 1:
                return None
            if not isinstance(nonce, str) or len(nonce) < 12 or len(nonce) > 64:
                return None
            if name is not None and (not isinstance(name, str) or len(name) > 200):
                return None
            if method == "none":
                if digest is not None:
                    return None
            elif not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                return None
            return OAuthClient(
                client_id=client_id,
                redirect_uris=redirects,
                token_endpoint_auth_method=method,
                client_name=name,
                secret_digest=digest,
                issued_at=issued_at,
            )
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, binascii.Error):
            return None

    def accepts_redirect(self, client_id: str, redirect_uri: str) -> bool:
        client = self.get(client_id)
        return client is not None and client.accepts_redirect(redirect_uri)

    def authenticates(self, client_id: str, client_secret: str, auth_method: str) -> bool:
        client = self.get(client_id)
        return (
            client is not None
            and client.token_endpoint_auth_method == auth_method
            and client.verifies_secret(client_secret)
        )


@dataclass(frozen=True)
class OAuthConfig:
    password: str
    server_url: str | None
    token_secret: bytes
    token_ttl: int = OAUTH_TOKEN_TTL_SECONDS
    registry: OAuthClientRegistry = field(default_factory=OAuthClientRegistry)
    pending_codes: dict[str, dict[str, Any]] = field(default_factory=dict)
    pending_codes_lock: threading.Lock = field(default_factory=threading.Lock)


def validate_redirect_uris(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_REDIRECT_URIS:
        raise ValueError(f"redirect_uris must contain between 1 and {MAX_REDIRECT_URIS} entries")
    redirects: list[str] = []
    for item in value:
        if not isinstance(item, str) or len(item) > 2048:
            raise ValueError("redirect_uri must be a string of at most 2048 characters")
        parsed = urllib.parse.urlsplit(item)
        if parsed.fragment or not parsed.scheme or not parsed.netloc or not parsed.hostname:
            raise ValueError("redirect_uri must be an absolute URI without a fragment")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("redirect_uri must not contain user information")
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme == "http" and hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("HTTP redirect_uri is allowed only for loopback hosts")
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("redirect_uri must use HTTPS or loopback HTTP")
        redirects.append(item)
    if len(set(redirects)) != len(redirects):
        raise ValueError("redirect_uris must be unique")
    return tuple(redirects)


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9\-._~]{43,128}", code_verifier):
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(expected, code_challenge)


def valid_pkce_challenge(code_challenge: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge) is not None


def create_access_token(config: OAuthConfig, server_url: str, *, client_id: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": server_url,
            "aud": server_url,
            "sub": client_id,
            "client_id": client_id,
            "iat": now,
            "exp": now + config.token_ttl,
            "scope": "mcp",
        },
        config.token_secret,
        algorithm="HS256",
    )


def validate_access_token(token: str, config: OAuthConfig, server_url: str) -> bool:
    try:
        claims = jwt.decode(
            token,
            config.token_secret,
            algorithms=["HS256"],
            audience=server_url,
            issuer=server_url,
        )
    except jwt.PyJWTError:
        return False
    client_id = claims.get("client_id")
    return isinstance(client_id, str) and config.registry.get(client_id) is not None


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError("Invalid client ID encoding")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _b64url(decoded) != value:
        raise ValueError("Non-canonical client ID encoding")
    return decoded


def _secret_digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _optional_text(value: Any, maximum: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:maximum]
