"""LicenseUserV3 -- license endpoint load tests.

List, filter, sort, and detail endpoints for /api/v3/license.
Includes slow license-filter queries (merged from rest_api_slow).
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class LicenseUserV3(AuthenticatedHttpUser):
    """Exercises license v3 REST API endpoints."""

    weight = 1
    wait_time = WAIT_TIME

    # -- List endpoints -------------------------------------------------

    @tag("v3", "license", "list", "readonly")
    @task
    def list_license(self) -> None:
        self.client.get(
            "/api/v3/license?total=true",
            name="/api/v3/license?total=true",
        )

    @tag("v3", "license", "list", "readonly")
    @task
    def list_license_sorted(self) -> None:
        self.client.get(
            "/api/v3/license?limit=10&offset=0&q=&sort=license:asc&total=true",
            name="/api/v3/license?limit=10&sort=license:asc&total=true",
        )

    @tag("v3", "license", "list", "readonly")
    @task
    def list_spdx_license(self) -> None:
        self.client.get(
            "/api/v3/license/spdx/license?total=true",
            name="/api/v3/license/spdx/license?total=true",
        )

    # -- Slow queries (merged from rest_api_slow) -----------------------

    @tag("v3", "license", "slow", "readonly")
    @task
    def license_asl_sorted(self) -> None:
        self.client.get(
            "/api/v3/license?q=ASL&sort=license:desc&total=true",
            name="/api/v3/license?q=ASL&sort=license:desc&total=true",
        )

    @tag("v3", "license", "slow", "readonly")
    @task
    def license_apache(self) -> None:
        self.client.get(
            "/api/v3/license?q=license~Apache&total=true",
            name="/api/v3/license?q=license~Apache&total=true",
        )

    @tag("v3", "license", "slow", "readonly")
    @task
    def license_gpl(self) -> None:
        self.client.get(
            "/api/v3/license?q=license~GPL&total=true",
            name="/api/v3/license?q=license~GPL&total=true",
        )

    @tag("v3", "license", "slow", "readonly")
    @task
    def spdx_license_apache(self) -> None:
        self.client.get(
            "/api/v3/license/spdx/license?q=apache&total=true",
            name="/api/v3/license/spdx/license?q=apache&total=true",
        )

    @tag("v3", "license", "slow", "readonly")
    @task
    def spdx_license_gpl(self) -> None:
        self.client.get(
            "/api/v3/license/spdx/license?q=gpl&total=true",
            name="/api/v3/license/spdx/license?q=gpl&total=true",
        )

    # -- Detail endpoints -----------------------------------------------

    @tag("v3", "license", "detail", "readonly")
    @task
    def get_spdx_license(self) -> None:
        if not SCENARIO.get_spdx_license:
            return
        lid = SCENARIO.get_spdx_license
        with self.client.get(
            f"/api/v3/license/spdx/license/{quote(lid, safe='')}",
            name=f"get_spdx_license[{lid}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
