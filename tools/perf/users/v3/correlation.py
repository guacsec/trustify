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
        self._verdict_page("offset=0&limit=25&total=false")

    def _verdict_page(self, query: str) -> None:
        """Keep distinct query costs separate and reject uncomputed benchmark data."""
        if not SCENARIO.get_correlation_sbom:
            return
        sbom_id = quote(SCENARIO.get_correlation_sbom, safe="")
        with self.client.get(
            f"/api/v3/correlation/sbom/{sbom_id}?{query}",
            name=f"/api/v3/correlation/sbom/{{sbom_id}}?{query}",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                return
            try:
                generation = response.json()["freshness"]["generation"]
            except (ValueError, KeyError, TypeError):
                response.failure("Missing verdict freshness metadata")
                return
            if generation is None:
                response.failure("Scenario SBOM has no completed verdict computation")

    @tag("v3", "correlation", "detail", "readonly")
    @task
    def get_sbom_correlation_with_total(self) -> None:
        self._verdict_page("offset=0&limit=25&total=true")

    @tag("v3", "correlation", "detail", "readonly")
    @task
    def get_sbom_correlation_next_page(self) -> None:
        self._verdict_page("offset=25&limit=25&total=false")

    @tag("v3", "correlation", "detail", "readonly")
    @task
    def get_sbom_correlation_count_only(self) -> None:
        self._verdict_page("offset=0&limit=0&total=true")

    @tag("v3", "correlation", "detail", "readonly")
    @task
    def get_sbom_verdict_freshness(self) -> None:
        self._verdict_page("offset=0&limit=0&total=false")

    @tag("v3", "correlation", "detail", "readonly")
    @task(2)
    def get_sbom_unmatched(self) -> None:
        if not SCENARIO.get_correlation_sbom:
            return
        sbom_id = quote(SCENARIO.get_correlation_sbom, safe="")
        self.client.get(
            f"/api/v3/correlation/sbom/{sbom_id}/unmatched?offset=0&limit=25&total=true",
            name="/api/v3/correlation/sbom/{sbom_id}/unmatched",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task
    def find_affected_sboms(self) -> None:
        self.client.get(
            "/api/v3/sbom?verdict_status=affected&offset=0&limit=25&total=true",
            name="/api/v3/sbom?verdict_status=affected",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task
    def find_affected_sboms_without_total(self) -> None:
        self.client.get(
            "/api/v3/sbom?verdict_status=affected&offset=0&limit=25&total=false",
            name="/api/v3/sbom?verdict_status=affected&total=false",
        )

    @tag("v3", "correlation", "list", "readonly")
    @task
    def find_affected_sboms_by_vulnerability(self) -> None:
        if not SCENARIO.get_vulnerability:
            return
        query = urlencode({
            "verdict_status": "affected",
            "verdict_vulnerability_id": SCENARIO.get_vulnerability,
            "offset": 0, "limit": 25, "total": "true",
        })
        self.client.get(
            f"/api/v3/sbom?{query}",
            name="/api/v3/sbom?verdict_status=affected&verdict_vulnerability_id={id}&total=true",
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
