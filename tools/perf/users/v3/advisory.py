"""AdvisoryUserV3 -- advisory endpoint load tests.

List, filter, sort, and detail endpoints for /api/v3/advisory.
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class AdvisoryUserV3(AuthenticatedHttpUser):
    """Exercises advisory v3 REST API endpoints."""

    weight = 2
    wait_time = WAIT_TIME

    # -- List endpoints -------------------------------------------------

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory(self) -> None:
        self.client.get(
            "/api/v3/advisory?total=true",
            name="/api/v3/advisory?total=true",
        )

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory_paginated(self) -> None:
        self.client.get(
            "/api/v3/advisory?offset=100&limit=10&total=true",
            name="/api/v3/advisory?offset=100&limit=10&total=true",
        )

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory_by_identifier(self) -> None:
        self.client.get(
            "/api/v3/advisory?q=identifier%3dCVE-2022-0981&total=true",
            name="/api/v3/advisory?q=identifier=CVE-2022-0981&total=true",
        )

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory_by_cve_prefix(self) -> None:
        self.client.get(
            "/api/v3/advisory?q=CVE-2021-&total=true",
            name="/api/v3/advisory?q=CVE-2021-&total=true",
        )

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory_by_title(self) -> None:
        self.client.get(
            "/api/v3/advisory?q=title~openssl&total=true",
            name="/api/v3/advisory?q=title~openssl&total=true",
        )

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory_by_modified(self) -> None:
        self.client.get(
            "/api/v3/advisory?q=modified>3 days ago&total=true",
            name="/api/v3/advisory?q=modified>3 days ago&total=true",
        )

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory_sorted(self) -> None:
        self.client.get(
            "/api/v3/advisory?sort=modified:desc&total=true",
            name="/api/v3/advisory?sort=modified:desc&total=true",
        )

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory_sorted_ingested(self) -> None:
        self.client.get(
            "/api/v3/advisory?limit=10&offset=0&sort=ingested:desc&q=&total=true",
            name="/api/v3/advisory?limit=10&sort=ingested:desc&total=true",
        )

    @tag("v3", "advisory", "list", "readonly")
    @task
    def list_advisory_deprecated(self) -> None:
        self.client.get(
            "/api/v3/advisory?deprecated=Consider&total=true",
            name="/api/v3/advisory?deprecated=Consider&total=true",
        )

    # -- Detail endpoints -----------------------------------------------

    @tag("v3", "advisory", "detail", "readonly")
    @task
    def get_advisory(self) -> None:
        if not SCENARIO.get_advisory:
            return
        uid = SCENARIO.get_advisory
        with self.client.get(
            f"/api/v3/advisory/urn:uuid:{uid}",
            name=f"get_advisory[{uid[:12]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "advisory", "detail", "readonly")
    @task
    def download_advisory(self) -> None:
        if not SCENARIO.download_advisory:
            return
        uid = SCENARIO.download_advisory
        with self.client.get(
            f"/api/v3/advisory/urn:uuid:{uid}/download",
            name=f"download_advisory[{uid[:12]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
