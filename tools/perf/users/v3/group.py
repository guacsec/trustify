"""GroupUserV3 -- SBOM group endpoint load tests.

List and detail endpoints for /api/v3/group/sbom.
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class GroupUserV3(AuthenticatedHttpUser):
    """Exercises SBOM group v3 REST API endpoints."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("v3", "group", "list", "readonly")
    @task
    def list_sbom_group(self) -> None:
        self.client.get(
            "/api/v3/group/sbom?total=true",
            name="/api/v3/group/sbom?total=true",
        )

    @tag("v3", "group", "list", "readonly")
    @task
    def list_sbom_group_totals(self) -> None:
        self.client.get(
            "/api/v3/group/sbom?totals=true&total=true",
            name="/api/v3/group/sbom?totals=true&total=true",
        )

    @tag("v3", "group", "list", "readonly")
    @task
    def list_sbom_group_parents(self) -> None:
        self.client.get(
            "/api/v3/group/sbom?parents=resolve&total=true",
            name="/api/v3/group/sbom?parents=resolve&total=true",
        )

    @tag("v3", "group", "detail", "readonly")
    @task
    def get_sbom_group(self) -> None:
        if not SCENARIO.get_sbom_group:
            return
        gid = SCENARIO.get_sbom_group
        with self.client.get(
            f"/api/v3/group/sbom/{quote(gid, safe='')}",
            name=f"get_sbom_group[{gid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "group", "detail", "readonly")
    @task
    def get_sbom_group_assignments(self) -> None:
        if not SCENARIO.get_sbom_group:
            return
        gid = SCENARIO.get_sbom_group
        with self.client.get(
            f"/api/v3/group/sbom-assignment/{quote(gid, safe='')}",
            name=f"get_sbom_group_assignments[{gid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
