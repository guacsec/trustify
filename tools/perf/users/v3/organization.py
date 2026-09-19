"""OrganizationUserV3 -- organization endpoint load tests.

List, sort, and detail endpoints for /api/v3/organization.
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class OrganizationUserV3(AuthenticatedHttpUser):
    """Exercises organization v3 REST API endpoints."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("v3", "organization", "list", "readonly")
    @task
    def list_organization(self) -> None:
        self.client.get(
            "/api/v3/organization?total=true",
            name="/api/v3/organization?total=true",
        )

    @tag("v3", "organization", "list", "readonly")
    @task
    def list_organization_sorted(self) -> None:
        self.client.get(
            "/api/v3/organization?sort=name:asc&total=true",
            name="/api/v3/organization?sort=name:asc&total=true",
        )

    @tag("v3", "organization", "detail", "readonly")
    @task
    def get_organization(self) -> None:
        if not SCENARIO.get_organization:
            return
        oid = SCENARIO.get_organization
        with self.client.get(
            f"/api/v3/organization/{quote(oid, safe='')}",
            name=f"get_organization[{oid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
