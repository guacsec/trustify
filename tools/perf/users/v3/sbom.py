"""SBOMUserV3 -- SBOM endpoint load tests.

List, filter, sort, detail, and license endpoints for /api/v3/sbom.
Includes slow license-filter queries (merged from rest_api_slow).
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class SBOMUserV3(AuthenticatedHttpUser):
    """Exercises SBOM v3 REST API endpoints."""

    weight = 2
    wait_time = WAIT_TIME

    # -- List endpoints -------------------------------------------------

    @tag("v3", "sbom", "list", "readonly")
    @task(2)
    def list_sbom(self) -> None:
        self.client.get(
            "/api/v3/sbom?total=true",
            name="/api/v3/sbom?total=true",
        )

    @tag("v3", "sbom", "list", "readonly")
    @task(2)
    def list_sbom_paginated(self) -> None:
        self.client.get(
            "/api/v3/sbom?offset=100&limit=10&total=true",
            name="/api/v3/sbom?offset=100&limit=10&total=true",
        )

    @tag("v3", "sbom", "list", "readonly")
    @task
    def list_sbom_by_name(self) -> None:
        self.client.get(
            "/api/v3/sbom?q=name~redhat&total=true",
            name="/api/v3/sbom?q=name~redhat&total=true",
        )

    @tag("v3", "sbom", "list", "readonly")
    @task
    def list_sbom_by_published(self) -> None:
        self.client.get(
            "/api/v3/sbom?q=published>2024-01-01&total=true",
            name="/api/v3/sbom?q=published>2024-01-01&total=true",
        )

    @tag("v3", "sbom", "list", "readonly")
    @task
    def list_sbom_sorted(self) -> None:
        self.client.get(
            "/api/v3/sbom?sort=ingested:desc&total=true",
            name="/api/v3/sbom?sort=ingested:desc&total=true",
        )

    @tag("v3", "sbom", "list", "readonly")
    @task
    def list_sbom_sorted_name(self) -> None:
        self.client.get(
            "/api/v3/sbom?limit=10&offset=0&sort=name:asc&q=&total=true",
            name="/api/v3/sbom?limit=10&sort=name:asc&total=true",
        )

    @tag("v3", "sbom", "list", "readonly")
    @task
    def list_sbom_by_label(self) -> None:
        self.client.get(
            "/api/v3/sbom?q=label:type=product&total=true",
            name="/api/v3/sbom?q=label:type=product&total=true",
        )

    @tag("v3", "sbom", "list", "readonly")
    @task
    def list_sbom_labels(self) -> None:
        self.client.get(
            "/api/v3/sbom-labels?total=true",
            name="/api/v3/sbom-labels?total=true",
        )

    @tag("v3", "sbom", "list", "readonly")
    @task
    def list_sbom_labels_filtered(self) -> None:
        self.client.get(
            "/api/v3/sbom-labels?limit=10&filter_text=&total=true",
            name="/api/v3/sbom-labels?limit=10&filter_text=&total=true",
        )

    # -- Slow queries (merged from rest_api_slow) -----------------------

    @tag("v3", "sbom", "slow", "readonly")
    @task
    def sbom_license_filter(self) -> None:
        self.client.get(
            "/api/v3/sbom?q=license~GPL&sort=name:desc&total=true",
            name="/api/v3/sbom?q=license~GPL&sort=name:desc&total=true",
        )

    # -- Detail endpoints -----------------------------------------------

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def get_sbom(self) -> None:
        if not SCENARIO.get_sbom:
            return
        key = SCENARIO.get_sbom
        with self.client.get(
            f"/api/v3/sbom/{quote(key, safe='')}",
            name=f"get_sbom[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def get_sbom_advisories(self) -> None:
        if not SCENARIO.get_sbom_advisories:
            return
        key = SCENARIO.get_sbom_advisories
        with self.client.get(
            f"/api/v3/sbom/{quote(key, safe='')}/advisory",
            name=f"get_sbom_advisories[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def get_sbom_advisories_by_uuid(self) -> None:
        if not SCENARIO.get_sbom_advisories_by_uuid:
            return
        uid = SCENARIO.get_sbom_advisories_by_uuid
        with self.client.get(
            f"/api/v3/sbom/urn%3Auuid%3A{uid}/advisory",
            name=f"get_sbom_advisories_by_uuid[{uid[:12]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def get_sbom_packages(self) -> None:
        if not SCENARIO.get_sbom_packages:
            return
        key = SCENARIO.get_sbom_packages
        with self.client.get(
            f"/api/v3/sbom/{quote(key, safe='')}/packages",
            name=f"get_sbom_packages[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def get_sbom_related(self) -> None:
        if not SCENARIO.get_sbom_related:
            return
        key = SCENARIO.get_sbom_related
        with self.client.get(
            f"/api/v3/sbom/{quote(key, safe='')}/related",
            name=f"get_sbom_related[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def get_sbom_license_ids(self) -> None:
        if not SCENARIO.sbom_license_ids:
            return
        key = SCENARIO.sbom_license_ids
        with self.client.get(
            f"/api/v3/sbom/{quote(key, safe='')}/all-license-ids",
            name=f"get_sbom_license_ids[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def download_sbom(self) -> None:
        if not SCENARIO.download_sbom:
            return
        key = SCENARIO.download_sbom
        with self.client.get(
            f"/api/v3/sbom/{quote(key, safe='')}/download",
            name=f"download_sbom[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def get_sbom_license_export(self) -> None:
        if not SCENARIO.get_sbom_license_export:
            return
        sid = SCENARIO.get_sbom_license_export
        with self.client.get(
            f"/api/v3/sbom/{quote(sid, safe='')}/license-export",
            name=f"get_sbom_license_export[{sid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def sbom_by_package(self) -> None:
        if not SCENARIO.sbom_by_package:
            return
        purl = SCENARIO.sbom_by_package
        with self.client.get(
            f"/api/v3/sbom/by-package?purl={quote(purl, safe='')}",
            name=f"sbom_by_package[{purl[:20]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail", "readonly")
    @task
    def count_sbom_by_package(self) -> None:
        if not SCENARIO.count_sbom_by_package:
            return
        purl = SCENARIO.count_sbom_by_package
        with self.client.get(
            "/api/v3/sbom/count-by-package",
            json=[{"purl": purl}],
            name=f"count_sbom_by_package[{purl[:20]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
