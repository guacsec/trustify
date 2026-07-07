"""Base user class with optional OIDC authentication.

All user classes should extend AuthenticatedHttpUser instead of
HttpUser directly.  When AUTH_DISABLED is not set (or false), the
OIDC token is acquired on_start and set as the default Authorization
header on the requests session.
"""

from __future__ import annotations

import logging

from locust import HttpUser

from auth import create_provider, is_auth_disabled, OidcTokenProvider

logger = logging.getLogger(__name__)

_provider: OidcTokenProvider | None = None


def _get_provider() -> OidcTokenProvider:
    """Lazily create and cache the singleton OIDC token provider."""
    global _provider  # noqa: PLW0603
    if _provider is None:
        _provider = create_provider()
    return _provider


class AuthenticatedHttpUser(HttpUser):
    """HttpUser subclass that injects an OIDC Bearer token on startup.

    When AUTH_DISABLED=true, behaves identically to plain HttpUser.
    """

    abstract = True

    def on_start(self) -> None:
        if is_auth_disabled():
            logger.debug("Auth disabled -- skipping OIDC token")
            return

        provider = _get_provider()
        token = provider.get_token()
        self.client.headers["Authorization"] = f"Bearer {token}"
        logger.info("OIDC Bearer token set for user %s", type(self).__name__)
