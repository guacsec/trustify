"""CorrelationUserV3 -- correlation engine endpoint load tests.

Exercises the read-heavy correlation endpoints. SBOM and advisory lookups use
IDs from the configured scenario file so requests target real snapshot data.
"""

from __future__ import annotations

from urllib.parse import quote, urlencode

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class CorrelationUserV3(AuthenticatedHttpUser):
    """Exercises correlation v3 REST API endpoints."""

    required_capability = "correlation"
    weight = 1
    wait_time = WAIT_TIME

    @tag("v3", "correlation", "detail", "readonly")
    @task(3)
    def get_sbom_correlation(self) -> None:
        if not SCENARIO.get_correlation_sbom:
            return
        sbom_id = quote(SCENARIO.get_correlation_sbom, safe="")
        self.client.get(
            f"/api/v3/correlation/sbom/{sbom_id}",
            name="/api/v3/correlation/sbom/{sbom_id}",
        )

    @tag("v3", "correlation", "detail", "readonly")
    @task(2)
    def get_sbom_correlation_with_unmatched(self) -> None:
        if not SCENARIO.get_correlation_sbom:
            return
        sbom_id = quote(SCENARIO.get_correlation_sbom, safe="")
        self.client.get(
            f"/api/v3/correlation/sbom/{sbom_id}?include_unmatched=true",
            name="/api/v3/correlation/sbom/{sbom_id}?include_unmatched=true",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task(2)
    def query_correlation(self) -> None:
        if not SCENARIO.correlation_query:
            return
        query = urlencode({"kind": "purl", "q": SCENARIO.correlation_query})
        self.client.get(
            f"/api/v3/correlation/query?{query}",
            name="/api/v3/correlation/query?kind=purl",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task
    def count_verdicts(self) -> None:
        if not SCENARIO.get_correlation_sbom:
            return
        self.client.post(
            "/api/v3/correlation/verdict-counts",
            json={"sbom_ids": [SCENARIO.get_correlation_sbom]},
            name="/api/v3/correlation/verdict-counts",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task
    def list_advisory_statements(self) -> None:
        if not SCENARIO.get_correlation_advisory:
            return
        advisory_id = quote(SCENARIO.get_correlation_advisory, safe="")
        self.client.get(
            f"/api/v3/correlation/advisory/{advisory_id}/statement"
            "?kind=purl&offset=0&limit=10&total=true",
            name="/api/v3/correlation/advisory/{advisory_id}/statement",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task
    def get_confidence(self) -> None:
        self.client.get(
            "/api/v3/correlation/confidence",
            name="/api/v3/correlation/confidence",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task
    def get_freshness(self) -> None:
        self.client.get(
            "/api/v3/correlation/freshness",
            name="/api/v3/correlation/freshness",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task
    def list_freshness_sboms(self) -> None:
        self.client.get(
            "/api/v3/correlation/freshness/sbom?offset=0&limit=10&total=true",
            name="/api/v3/correlation/freshness/sbom?offset=0&limit=10&total=true",
        )
