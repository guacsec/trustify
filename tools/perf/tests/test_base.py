"""Compression negotiation and decoding checks for the shared Locust client."""

from __future__ import annotations

import io
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

# These unit tests do not spawn Locust users or need gevent monkey-patching.
with patch.dict(os.environ, {"LOCUST_SKIP_MONKEY_PATCH": "1"}):
    from users import base

import requests
from urllib3.response import HTTPResponse

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd


class CompressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.user = SimpleNamespace(
            client=SimpleNamespace(headers=requests.utils.default_headers())
        )

    def test_advertises_zstd_and_fallbacks(self) -> None:
        with patch.object(base, "_NO_COMPRESSION", False), patch.object(
            base, "is_auth_disabled", return_value=True
        ):
            base.AuthenticatedHttpUser.on_start(self.user)

        self.assertEqual(
            self.user.client.headers["Accept-Encoding"], "zstd, gzip, deflate, br"
        )

    def test_no_compression_overrides_session_defaults(self) -> None:
        with patch.object(base, "_NO_COMPRESSION", True), patch.object(
            base, "is_auth_disabled", return_value=True
        ), patch.object(HTTPResponse, "CONTENT_DECODERS", ["gzip", "deflate"]):
            base.AuthenticatedHttpUser.on_start(self.user)

        self.assertEqual(self.user.client.headers["Accept-Encoding"], "identity")

    def test_missing_decoder_fails_before_advertising_zstd(self) -> None:
        with patch.object(base, "_NO_COMPRESSION", False), patch.object(
            HTTPResponse, "CONTENT_DECODERS", ["gzip", "deflate"]
        ):
            with self.assertRaisesRegex(RuntimeError, "Zstd response decoding"):
                base.AuthenticatedHttpUser.on_start(self.user)

    def test_authentication_is_preserved(self) -> None:
        provider = SimpleNamespace(get_token=lambda: "test-token")
        with patch.object(base, "_NO_COMPRESSION", False), patch.object(
            base, "is_auth_disabled", return_value=False
        ), patch.object(base, "_get_provider", return_value=provider):
            base.AuthenticatedHttpUser.on_start(self.user)

        self.assertEqual(self.user.client.headers["Authorization"], "Bearer test-token")
        self.assertEqual(
            self.user.client.headers["Accept-Encoding"], "zstd, gzip, deflate, br"
        )

    def test_zstd_response_is_decoded_before_json_parsing(self) -> None:
        response = requests.Response()
        response.status_code = 200
        response.raw = HTTPResponse(
            body=io.BytesIO(zstd.compress(b'{"items": [], "total": 0}')),
            headers={"Content-Encoding": "zstd"},
            preload_content=False,
        )

        self.assertEqual(response.json(), {"items": [], "total": 0})


if __name__ == "__main__":
    unittest.main()
