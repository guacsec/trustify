"""AnalysisUserV3 -- analysis and graph rendering v3 endpoints (weight 2).

Analysis status, CPE lookup, scenario-driven component search, and
SBOM graph rendering. Component search accepts a list of keys in the
scenario file and cycles through them round-robin per request.
"""

from __future__ import annotations

import itertools
from urllib.parse import quote

from locust import HttpUser, tag, task
from config import WAIT_TIME

from scenario import SCENARIO

_HARDCODED_CPE = "cpe:/a:redhat:openshift_container_platform:4.17::el9"


class AnalysisUserV3(HttpUser):
    """Exercises trustify v3 analysis and graph endpoints."""

    weight = 2
    wait_time = WAIT_TIME
    _component_cycle = itertools.cycle(
        SCENARIO.get_analysis_component
    ) if SCENARIO.get_analysis_component else None

    @tag("v3", "analysis")
    @task
    def analysis_status(self) -> None:
        self.client.get(
            "/api/v3/analysis/status",
            name="/api/v3/analysis/status",
        )

    @tag("v3", "analysis")
    @task
    def analysis_by_cpe(self) -> None:
        self.client.get(
            f"/api/v3/analysis/latest/component/{quote(_HARDCODED_CPE, safe='')}",
            name="analysis_by_cpe",
        )

    @tag("v3", "analysis", "detail")
    @task
    def get_analysis_component(self) -> None:
        
        if not self._component_cycle:
            return
        key = next(self._component_cycle)
        with self.client.get(
            f"/api/v3/analysis/component/{quote(key, safe='')}",
            name=f"get_analysis_component[{key[:20]}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "analysis", "detail")
    @task
    def render_sbom_graph_dot(self) -> None:
        if not SCENARIO.render_sbom_graph:
            return
        sid = SCENARIO.render_sbom_graph
        with self.client.get(
            f"/api/v3/analysis/sbom/{quote(sid, safe='')}/render.dot",
            name=f"render_sbom_graph_dot[{sid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
