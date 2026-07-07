"""OIDC token provider for authenticated load testing.

Performs OpenID Connect discovery and acquires tokens via the OAuth2
client_credentials grant.  Tokens are cached and refreshed proactively
before expiry.

Environment variables
---------------------
ISSUER_URL          OIDC issuer URL (required unless AUTH_DISABLED=true).
CLIENT_ID           OAuth2 client ID (required unless AUTH_DISABLED=true).
CLIENT_SECRET       OAuth2 client secret (required unless AUTH_DISABLED=true).
OIDC_REFRESH_BEFORE Seconds before expiry to refresh (default: 30).
AUTH_DISABLED        Set to "true" or "1" to skip authentication entirely.
"""

from __future__ import annotations

import logging
import os
import threading
import time

import requests as _requests

logger = logging.getLogger(__name__)

_AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "").lower() in ("true", "1")
_REFRESH_BEFORE = int(os.environ.get("OIDC_REFRESH_BEFORE", "30"))


def is_auth_disabled() -> bool:
    """Return True when authentication is disabled."""
    return _AUTH_DISABLED


class OidcTokenProvider:
    """Acquires and caches OIDC tokens using the client_credentials grant."""

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        client_secret: str,
        refresh_before: int = _REFRESH_BEFORE,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_before = refresh_before
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()
        self._token_endpoint = self._discover_token_endpoint(issuer_url)

    def _discover_token_endpoint(self, issuer_url: str) -> str:
        """Fetch the OIDC discovery document and extract the token endpoint."""
        url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        logger.info("OIDC discovery: %s", url)
        resp = _requests.get(url, timeout=30)
        resp.raise_for_status()
        endpoint = resp.json().get("token_endpoint")
        if not endpoint:
            msg = (
                f"No 'token_endpoint' in OIDC discovery document at {url}"
            )
            raise ValueError(msg)
        logger.info("OIDC token endpoint: %s", endpoint)
        return endpoint

    def _fetch_token(self) -> None:
        """Request a new token using the client_credentials grant."""
        logger.debug("Requesting new OIDC token via client_credentials")
        resp = _requests.post(
            self._token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        expires_in = body.get("expires_in", 300)
        self._expires_at = time.monotonic() + expires_in
        logger.info(
            "OIDC token acquired (expires_in=%ds, refresh_before=%ds)",
            expires_in,
            self._refresh_before,
        )

    def _needs_refresh(self) -> bool:
        if self._token is None:
            return True
        return time.monotonic() >= (self._expires_at - self._refresh_before)

    def get_token(self) -> str:
        """Return a valid access token, refreshing if necessary."""
        if not self._needs_refresh():
            return self._token  # type: ignore[return-value]

        with self._lock:
            if self._needs_refresh():
                self._fetch_token()
            return self._token  # type: ignore[return-value]


def create_provider() -> OidcTokenProvider:
    """Build an OidcTokenProvider from environment variables.

    Raises ValueError if required env vars are missing.
    """
    issuer_url = os.environ.get("ISSUER_URL", "")
    client_id = os.environ.get("CLIENT_ID", "")
    client_secret = os.environ.get("CLIENT_SECRET", "")

    missing = []
    if not issuer_url:
        missing.append("ISSUER_URL")
    if not client_id:
        missing.append("CLIENT_ID")
    if not client_secret:
        missing.append("CLIENT_SECRET")
    if missing:
        msg = (
            "OIDC authentication is enabled but the following "
            f"environment variables are missing: {', '.join(missing)}. "
            "Set them or disable auth with AUTH_DISABLED=true."
        )
        raise ValueError(msg)

    return OidcTokenProvider(
        issuer_url=issuer_url,
        client_id=client_id,
        client_secret=client_secret,
    )
