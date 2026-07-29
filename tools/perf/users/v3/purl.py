"""PurlUserV3 -- pURL endpoint load tests.

List, filter, sort, detail, and recommend endpoints for /api/v3/purl.
Includes slow license-filter queries (merged from rest_api_slow).
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class PurlUserV3(AuthenticatedHttpUser):
    """Exercises pURL v3 REST API endpoints."""

    weight = 2
    wait_time = WAIT_TIME

    # -- List endpoints -------------------------------------------------

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl(self) -> None:
        self.client.get(
            "/api/v3/purl?total=true",
            name="/api/v3/purl?total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_paginated(self) -> None:
        self.client.get(
            "/api/v3/purl?offset=100&limit=10&total=true",
            name="/api/v3/purl?offset=100&limit=10&total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_by_name(self) -> None:
        self.client.get(
            "/api/v3/purl?q=curl&total=true",
            name="/api/v3/purl?q=curl&total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_by_exact_name(self) -> None:
        self.client.get(
            "/api/v3/purl?q=name=curl&total=true",
            name="/api/v3/purl?q=name=curl&total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_by_type(self) -> None:
        self.client.get(
            "/api/v3/purl?q=purl:ty=rpm&total=true",
            name="/api/v3/purl?q=purl:ty=rpm&total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_by_namespace(self) -> None:
        self.client.get(
            "/api/v3/purl?q=purl:namespace=redhat&total=true",
            name="/api/v3/purl?q=purl:namespace=redhat&total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_sorted(self) -> None:
        self.client.get(
            "/api/v3/purl?sort=purl:name:asc&total=true",
            name="/api/v3/purl?sort=purl:name:asc&total=true",
        )

    # -- Base pURL endpoints --------------------------------------------

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_base(self) -> None:
        self.client.get(
            "/api/v3/purl/base?total=true",
            name="/api/v3/purl/base?total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_base_by_type(self) -> None:
        self.client.get(
            "/api/v3/purl/base?q=type=rpm&total=true",
            name="/api/v3/purl/base?q=type=rpm&total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_base_by_ns(self) -> None:
        self.client.get(
            "/api/v3/purl/base?q=namespace=redhat&total=true",
            name="/api/v3/purl/base?q=namespace=redhat&total=true",
        )

    @tag("v3", "purl", "list", "readonly")
    @task
    def list_purl_base_sorted(self) -> None:
        self.client.get(
            "/api/v3/purl/base?sort=name:asc&total=true",
            name="/api/v3/purl/base?sort=name:asc&total=true",
        )

    # -- Slow queries (merged from rest_api_slow) -----------------------

    @tag("v3", "purl", "slow", "readonly")
    @task
    def purl_license_filter(self) -> None:
        self.client.get(
            "/api/v3/purl",
            params={
                "q": "license~GPLv3+ with exceptions|Apache",
                "sort": "name:desc",
                "total": "true",
            },
            name="/api/v3/purl?q=license~GPLv3+...&sort=name:desc&total=true",
        )

    # -- Detail endpoints -----------------------------------------------

    @tag("v3", "purl", "detail", "readonly")
    @task
    def get_purl_details(self) -> None:
        if not SCENARIO.get_purl_details:
            return
        pid = SCENARIO.get_purl_details
        with self.client.get(
            f"/api/v3/purl/{quote(pid, safe='')}",
            name=f"get_purl_details[{pid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "purl", "detail", "readonly")
    @task
    def get_base_purl(self) -> None:
        if not SCENARIO.get_base_purl:
            return
        key = SCENARIO.get_base_purl
        with self.client.get(
            f"/api/v3/purl/base/{quote(key, safe='')}",
            name=f"get_base_purl[{key[:20]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    # -- Recommend (mutating) -------------------------------------------

    @tag("v3", "purl", "mutate")
    @task(3)
    def get_recommendations(self) -> None:
        if not SCENARIO.get_recommendations:
            return
        batch = SCENARIO.get_recommendations[:25]
        with self.client.post(
            "/api/v3/purl/recommend",
            json={"purls": batch},
            name=f"get_recommendations[batch={len(batch)}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
