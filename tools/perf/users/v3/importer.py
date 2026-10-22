"""ImporterUserV3 -- importer endpoint load tests.

Importer endpoints: the list from /api/v4/importer (the v3 list is deprecated),
detail and reports from /api/v3/importer.
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class ImporterUserV3(AuthenticatedHttpUser):
    """Exercises importer v3 REST API endpoints."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("v3", "importer", "list", "readonly")
    @task
    def list_importer(self) -> None:
        self.client.get(
            "/api/v4/importer?total=true",
            name="/api/v4/importer?total=true",
        )

    @tag("v3", "importer", "detail", "readonly")
    @task
    def get_importer(self) -> None:
        if not SCENARIO.get_importer:
            return
        name = SCENARIO.get_importer
        with self.client.get(
            f"/api/v3/importer/{quote(name, safe='')}",
            name="/api/v3/importer/{name}",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "importer", "detail", "readonly")
    @task
    def get_importer_report(self) -> None:
        if not SCENARIO.get_importer:
            return
        name = SCENARIO.get_importer
        with self.client.get(
            f"/api/v3/importer/{quote(name, safe='')}/report",
            name="/api/v3/importer/{name}/report",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
