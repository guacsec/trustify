"""RestAPIUserSlowV3 -- license-heavy v3 queries that tend to be slow (weight 1).

These queries combine license filters and sorting across large result
sets, producing heavier database load.
"""

from __future__ import annotations

from locust import HttpUser, tag, task
from config import WAIT_TIME


class RestAPIUserSlowV3(HttpUser):
    """Slow license-related queries against the trustify v3 REST API."""

    weight = 2
    wait_time = WAIT_TIME

    @tag("v3", "license", "slow")
    @task
    def license_asl_sorted(self) -> None:
        self.client.get(
            "/api/v3/license?q=ASL&sort=license:desc&total=true",
            name="/api/v3/license?q=ASL&sort=license:desc&total=true",
        )

    @tag("v3", "license", "slow")
    @task
    def license_apache(self) -> None:
        self.client.get(
            "/api/v3/license?q=license~Apache&total=true",
            name="/api/v3/license?q=license~Apache&total=true",
        )

    @tag("v3", "license", "slow")
    @task
    def license_gpl(self) -> None:
        self.client.get(
            "/api/v3/license?q=license~GPL&total=true",
            name="/api/v3/license?q=license~GPL&total=true",
        )

    @tag("v3", "license", "slow")
    @task
    def spdx_license_apache(self) -> None:
        self.client.get(
            "/api/v3/license/spdx/license?q=apache&total=true",
            name="/api/v3/license/spdx/license?q=apache&total=true",
        )

    @tag("v3", "license", "slow")
    @task
    def spdx_license_gpl(self) -> None:
        self.client.get(
            "/api/v3/license/spdx/license?q=gpl&total=true",
            name="/api/v3/license/spdx/license?q=gpl&total=true",
        )

    @tag("v3", "purl", "slow")
    @task
    def purl_license_filter(self) -> None:
        self.client.get(
            "/api/v3/purl",
            params={
                "q": "license~GPLv3+ with exceptions|Apache",
                "sort": "name:desc",
                "total": "true",
            },
            name="/api/v3/purl?q=license~GPLv3+...&sort=name:desc&total=true",
        )

    @tag("v3", "sbom", "slow")
    @task
    def sbom_license_filter(self) -> None:
        self.client.get(
            "/api/v3/sbom?q=license~GPL&sort=name:desc&total=true",
            name="/api/v3/sbom?q=license~GPL&sort=name:desc&total=true",
        )
