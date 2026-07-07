"""RestAPIUserSlowV2 -- license-heavy v2 queries that tend to be slow (weight 1).

These queries combine license filters and sorting across large result
sets, producing heavier database load.
"""

from __future__ import annotations

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser


class RestAPIUserSlowV2(AuthenticatedHttpUser):
    """Slow license-related queries against the trustify v2 REST API."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("v2", "license", "slow")
    @task
    def license_asl_sorted(self) -> None:
        self.client.get(
            "/api/v2/license?q=ASL&sort=license:desc",
            name="/api/v2/license?q=ASL&sort=license:desc",
        )

    @tag("v2", "license", "slow")
    @task
    def license_apache(self) -> None:
        self.client.get(
            "/api/v2/license?q=license~Apache",
            name="/api/v2/license?q=license~Apache",
        )

    @tag("v2", "license", "slow")
    @task
    def license_gpl(self) -> None:
        self.client.get(
            "/api/v2/license?q=license~GPL",
            name="/api/v2/license?q=license~GPL",
        )

    @tag("v2", "license", "slow")
    @task
    def spdx_license_apache(self) -> None:
        self.client.get(
            "/api/v2/license/spdx/license?q=apache",
            name="/api/v2/license/spdx/license?q=apache",
        )

    @tag("v2", "license", "slow")
    @task
    def spdx_license_gpl(self) -> None:
        self.client.get(
            "/api/v2/license/spdx/license?q=gpl",
            name="/api/v2/license/spdx/license?q=gpl",
        )

    @tag("v2", "purl", "slow")
    @task
    def purl_license_filter(self) -> None:
        self.client.get(
            "/api/v2/purl",
            params={
                "q": "license~GPLv3+ with exceptions|Apache",
                "sort": "name:desc",
            },
            name="/api/v2/purl?q=license~GPLv3+...&sort=name:desc",
        )

    @tag("v2", "sbom", "slow")
    @task
    def sbom_license_filter(self) -> None:
        self.client.get(
            "/api/v2/sbom?q=license~GPL&sort=name:desc",
            name="/api/v2/sbom?q=license~GPL&sort=name:desc",
        )
