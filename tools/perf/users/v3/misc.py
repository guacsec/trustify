"""MiscUserV3 -- miscellaneous endpoint load tests.

Well-known endpoint and UI helper endpoints.
"""

from __future__ import annotations

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser


class MiscUserV3(AuthenticatedHttpUser):
    """Exercises miscellaneous v3 endpoints."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("v3", "misc", "readonly")
    @task
    def well_known(self) -> None:
        self.client.get(
            "/.well-known/trustify",
            name="/.well-known/trustify",
        )

    @tag("v3", "misc", "mutate")
    @task
    def post_extract_sbom_purls(self) -> None:
        payload = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "locust-test",
            "documentNamespace": "https://example.com/locust",
            "packages": [],
        }
        self.client.post(
            "/api/v3/ui/extract-sbom-purls",
            json=payload,
            name="post_extract_sbom_purls",
        )
