"""Base user class with optional OIDC authentication and compression.

All user classes should extend AuthenticatedHttpUser instead of
HttpUser directly.  When AUTH_DISABLED is not set (or false), the
OIDC token is acquired on_start and set as the default Authorization
header on the requests session.

Compression (zstd/gzip/deflate/br) is enabled by default to match real
browser/client behaviour.  Set TOOLS_PERF_NO_COMPRESSION=1 to
disable it and measure raw uncompressed transfer cost.
"""

from __future__ import annotations

import logging
import os

from locust import HttpUser
from urllib3.response import HTTPResponse

from auth import create_provider, is_auth_disabled, OidcTokenProvider

logger = logging.getLogger(__name__)

_provider: OidcTokenProvider | None = None

_NO_COMPRESSION = os.environ.get(
    "TOOLS_PERF_NO_COMPRESSION", ""
).lower() in ("1", "true", "yes")


def _get_provider() -> OidcTokenProvider:
    """Lazily create and cache the singleton OIDC token provider."""
    global _provider  # noqa: PLW0603
    if _provider is None:
        _provider = create_provider()
    return _provider


class AuthenticatedHttpUser(HttpUser):
    """HttpUser subclass that injects auth and compression headers.

    When AUTH_DISABLED=true, skips OIDC authentication.
    When TOOLS_PERF_NO_COMPRESSION=1, requests identity encoding explicitly.
    """

    abstract = True

    def on_start(self) -> None:
        if _NO_COMPRESSION:
            self.client.headers["Accept-Encoding"] = "identity"
        else:
            if "zstd" not in HTTPResponse.CONTENT_DECODERS:
                raise RuntimeError(
                    "Zstd response decoding is unavailable. Run 'uv sync' in "
                    "tools/perf or install 'urllib3[zstd]==2.8.0'."
                )
            self.client.headers["Accept-Encoding"] = "zstd, gzip, deflate, br"

        if is_auth_disabled():
            logger.debug("Auth disabled -- skipping OIDC token")
            return

        provider = _get_provider()
        token = provider.get_token()
        self.client.headers["Authorization"] = f"Bearer {token}"
        logger.info("OIDC Bearer token set for user %s", type(self).__name__)
