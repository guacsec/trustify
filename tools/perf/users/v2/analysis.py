"""AnalysisUserV2 -- analysis and graph rendering v2 endpoints (weight 1).

Analysis status, scenario-driven component search, and SBOM graph
rendering. Component search accepts a list of keys in the scenario
file and picks one at random per request.
"""

from __future__ import annotations

import random
from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO

# NOTE: v3 has analysis_by_cpe using a hardcoded CPE; this endpoint does
# not exist in v2, so there is no equivalent task here.


class AnalysisUserV2(AuthenticatedHttpUser):
    """Exercises trustify v2 analysis and graph endpoints."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("v2", "analysis")
    @task
    def analysis_status(self) -> None:
        self.client.get(
            "/api/v2/analysis/status",
            name="/api/v2/analysis/status",
        )

    @tag("v2", "analysis", "detail")
    @task
    def get_analysis_component(self) -> None:
        if not SCENARIO.get_analysis_component:
            return
        key = random.choice(SCENARIO.get_analysis_component)  # noqa: S311
        with self.client.get(
            f"/api/v2/analysis/component/{quote(key, safe='')}",
            name=f"v2/get_analysis_component[{key[:20]}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "analysis", "detail")
    @task
    def render_sbom_graph_dot(self) -> None:
        if not SCENARIO.render_sbom_graph:
            return
        sid = SCENARIO.render_sbom_graph
        with self.client.get(
            f"/api/v2/analysis/sbom/{quote(sid, safe='')}/render.dot",
            name=f"v2/render_sbom_graph_dot[{sid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
