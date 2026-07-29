"""ProductUserV3 -- product endpoint load tests.

List, filter, sort, and detail endpoints for /api/v3/product.
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class ProductUserV3(AuthenticatedHttpUser):
    """Exercises product v3 REST API endpoints."""

    weight = 1
    wait_time = WAIT_TIME

    # -- List endpoints -------------------------------------------------

    @tag("v3", "product", "list", "readonly")
    @task
    def list_product(self) -> None:
        self.client.get(
            "/api/v3/product?total=true",
            name="/api/v3/product?total=true",
        )

    @tag("v3", "product", "list", "readonly")
    @task
    def list_product_by_name(self) -> None:
        self.client.get(
            "/api/v3/product?q=name~openshift&total=true",
            name="/api/v3/product?q=name~openshift&total=true",
        )

    @tag("v3", "product", "list", "readonly")
    @task
    def list_product_sorted(self) -> None:
        self.client.get(
            "/api/v3/product?sort=name:asc&total=true",
            name="/api/v3/product?sort=name:asc&total=true",
        )

    # -- Detail endpoints -----------------------------------------------

    @tag("v3", "product", "detail", "readonly")
    @task
    def get_product(self) -> None:
        if not SCENARIO.get_product:
            return
        pid = SCENARIO.get_product
        with self.client.get(
            f"/api/v3/product/{quote(pid, safe='')}",
            name=f"get_product[{pid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
