"""WeaknessUserV3 -- weakness/CWE endpoint load tests.

List, filter, sort, and detail endpoints for /api/v3/weakness.
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class WeaknessUserV3(AuthenticatedHttpUser):
    """Exercises weakness v3 REST API endpoints."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("v3", "weakness", "list", "readonly")
    @task
    def list_weakness(self) -> None:
        self.client.get(
            "/api/v3/weakness?total=true",
            name="/api/v3/weakness?total=true",
        )

    @tag("v3", "weakness", "list", "readonly")
    @task
    def list_weakness_by_desc(self) -> None:
        self.client.get(
            "/api/v3/weakness?q=description~injection&total=true",
            name="/api/v3/weakness?q=description~injection&total=true",
        )

    @tag("v3", "weakness", "list", "readonly")
    @task
    def list_weakness_sorted(self) -> None:
        self.client.get(
            "/api/v3/weakness?sort=id:asc&total=true",
            name="/api/v3/weakness?sort=id:asc&total=true",
        )

    @tag("v3", "weakness", "detail", "readonly")
    @task
    def get_weakness(self) -> None:
        if not SCENARIO.get_weakness:
            return
        wid = SCENARIO.get_weakness
        with self.client.get(
            f"/api/v3/weakness/{quote(wid, safe='')}",
            name=f"get_weakness[{wid}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
