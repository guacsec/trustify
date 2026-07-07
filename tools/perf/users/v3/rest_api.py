"""RestAPIUserV3 -- main REST API v3 load test (weight 10).

List, filter, sort, and detail endpoints for advisory, vulnerability,
SBOM, PURL, product, organization, importer, weakness, and license.
Scenario-driven detail lookups require TOOLS_PERF_SCENARIO_FILE.
"""

from __future__ import annotations

from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class RestAPIUserV3(AuthenticatedHttpUser):
    """Exercises the trustify v3 REST API with realistic query patterns."""

    weight = 2
    wait_time = WAIT_TIME

    # -- Advisory list endpoints ----------------------------------------

    @tag("v3", "advisory", "list")
    @task
    def list_advisory(self) -> None:
        self.client.get(
            "/api/v3/advisory?total=true",
            name="/api/v3/advisory?total=true",
        )

    @tag("v3", "advisory", "list")
    @task
    def list_advisory_paginated(self) -> None:
        self.client.get(
            "/api/v3/advisory?offset=100&limit=10&total=true",
            name="/api/v3/advisory?offset=100&limit=10&total=true",
        )

    @tag("v3", "advisory", "list")
    @task
    def list_advisory_by_identifier(self) -> None:
        self.client.get(
            "/api/v3/advisory?q=identifier%3dCVE-2022-0981&total=true",
            name="/api/v3/advisory?q=identifier=CVE-2022-0981&total=true",
        )

    @tag("v3", "advisory", "list")
    @task
    def list_advisory_by_cve_prefix(self) -> None:
        self.client.get(
            "/api/v3/advisory?q=CVE-2021-&total=true",
            name="/api/v3/advisory?q=CVE-2021-&total=true",
        )

    @tag("v3", "advisory", "list")
    @task
    def list_advisory_by_title(self) -> None:
        self.client.get(
            "/api/v3/advisory?q=title~openssl&total=true",
            name="/api/v3/advisory?q=title~openssl&total=true",
        )

    @tag("v3", "advisory", "list")
    @task
    def list_advisory_by_modified(self) -> None:
        self.client.get(
            "/api/v3/advisory?q=modified>3 days ago&total=true",
            name="/api/v3/advisory?q=modified>3 days ago&total=true",
        )

    @tag("v3", "advisory", "list")
    @task
    def list_advisory_sorted(self) -> None:
        self.client.get(
            "/api/v3/advisory?sort=modified:desc&total=true",
            name="/api/v3/advisory?sort=modified:desc&total=true",
        )

    @tag("v3", "advisory", "list")
    @task
    def list_advisory_sorted_ingested(self) -> None:
        self.client.get(
            "/api/v3/advisory?limit=10&offset=0&sort=ingested:desc&q=&total=true",
            name="/api/v3/advisory?limit=10&sort=ingested:desc&total=true",
        )

    @tag("v3", "advisory", "list")
    @task
    def list_advisory_deprecated(self) -> None:
        self.client.get(
            "/api/v3/advisory?deprecated=Consider&total=true",
            name="/api/v3/advisory?deprecated=Consider&total=true",
        )

    # -- Vulnerability list endpoints -----------------------------------

    @tag("v3", "vulnerability", "list")
    @task
    def list_vulnerability(self) -> None:
        self.client.get(
            "/api/v3/vulnerability?total=true",
            name="/api/v3/vulnerability?total=true",
        )

    @tag("v3", "vulnerability", "list")
    @task
    def list_vulnerability_paginated(self) -> None:
        self.client.get(
            "/api/v3/vulnerability?offset=100&limit=10&total=true",
            name="/api/v3/vulnerability?offset=100&limit=10&total=true",
        )

    @tag("v3", "vulnerability", "list")
    @task
    def list_vulnerability_high(self) -> None:
        self.client.get(
            "/api/v3/vulnerability?q=base_severity=high&total=true",
            name="/api/v3/vulnerability?q=base_severity=high&total=true",
        )

    @tag("v3", "vulnerability", "list")
    @task
    def list_vulnerability_score(self) -> None:
        self.client.get(
            "/api/v3/vulnerability?q=base_score>=7.0&total=true",
            name="/api/v3/vulnerability?q=base_score>=7.0&total=true",
        )

    @tag("v3", "vulnerability", "list")
    @task
    def list_vulnerability_cwe(self) -> None:
        self.client.get(
            "/api/v3/vulnerability?q=cwes=CWE-79&total=true",
            name="/api/v3/vulnerability?q=cwes=CWE-79&total=true",
        )

    @tag("v3", "vulnerability", "list")
    @task
    def list_vulnerability_sorted(self) -> None:
        self.client.get(
            "/api/v3/vulnerability?sort=base_score:desc&total=true",
            name="/api/v3/vulnerability?sort=base_score:desc&total=true",
        )

    # -- SBOM list endpoints --------------------------------------------

    @tag("v3", "sbom", "list")
    @task(2)
    def list_sbom(self) -> None:
        self.client.get(
            "/api/v3/sbom?total=true",
            name="/api/v3/sbom?total=true",
        )

    @tag("v3", "sbom", "list")
    @task(2)
    def list_sbom_paginated(self) -> None:
        self.client.get(
            "/api/v3/sbom?offset=100&limit=10&total=true",
            name="/api/v3/sbom?offset=100&limit=10&total=true",
        )

    @tag("v3", "sbom", "list")
    @task
    def list_sbom_by_name(self) -> None:
        self.client.get(
            "/api/v3/sbom?q=name~redhat&total=true",
            name="/api/v3/sbom?q=name~redhat&total=true",
        )

    @tag("v3", "sbom", "list")
    @task
    def list_sbom_by_published(self) -> None:
        self.client.get(
            "/api/v3/sbom?q=published>2024-01-01&total=true",
            name="/api/v3/sbom?q=published>2024-01-01&total=true",
        )

    @tag("v3", "sbom", "list")
    @task
    def list_sbom_sorted(self) -> None:
        self.client.get(
            "/api/v3/sbom?sort=ingested:desc&total=true",
            name="/api/v3/sbom?sort=ingested:desc&total=true",
        )

    @tag("v3", "sbom", "list")
    @task
    def list_sbom_sorted_name(self) -> None:
        self.client.get(
            "/api/v3/sbom?limit=10&offset=0&sort=name:asc&q=&total=true",
            name="/api/v3/sbom?limit=10&sort=name:asc&total=true",
        )

    @tag("v3", "sbom", "list")
    @task
    def list_sbom_by_label(self) -> None:
        self.client.get(
            "/api/v3/sbom?q=label:type=product&total=true",
            name="/api/v3/sbom?q=label:type=product&total=true",
        )

    @tag("v3", "sbom", "list")
    @task
    def list_sbom_labels(self) -> None:
        self.client.get(
            "/api/v3/sbom-labels?total=true",
            name="/api/v3/sbom-labels?total=true",
        )

    @tag("v3", "sbom", "list")
    @task
    def list_sbom_labels_filtered(self) -> None:
        self.client.get(
            "/api/v3/sbom-labels?limit=10&filter_text=&total=true",
            name="/api/v3/sbom-labels?limit=10&filter_text=&total=true",
        )

    # -- PURL list endpoints --------------------------------------------

    @tag("v3", "purl", "list")
    @task
    def list_purl(self) -> None:
        self.client.get(
            "/api/v3/purl?total=true",
            name="/api/v3/purl?total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_paginated(self) -> None:
        self.client.get(
            "/api/v3/purl?offset=100&limit=10&total=true",
            name="/api/v3/purl?offset=100&limit=10&total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_by_name(self) -> None:
        self.client.get(
            "/api/v3/purl?q=curl&total=true",
            name="/api/v3/purl?q=curl&total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_by_exact_name(self) -> None:
        self.client.get(
            "/api/v3/purl?q=name=curl&total=true",
            name="/api/v3/purl?q=name=curl&total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_by_type(self) -> None:
        self.client.get(
            "/api/v3/purl?q=purl:ty=rpm&total=true",
            name="/api/v3/purl?q=purl:ty=rpm&total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_by_namespace(self) -> None:
        self.client.get(
            "/api/v3/purl?q=purl:namespace=redhat&total=true",
            name="/api/v3/purl?q=purl:namespace=redhat&total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_sorted(self) -> None:
        self.client.get(
            "/api/v3/purl?sort=purl:name:asc&total=true",
            name="/api/v3/purl?sort=purl:name:asc&total=true",
        )

    # -- PURL base endpoints --------------------------------------------

    @tag("v3", "purl", "list")
    @task
    def list_purl_base(self) -> None:
        self.client.get(
            "/api/v3/purl/base?total=true",
            name="/api/v3/purl/base?total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_base_by_type(self) -> None:
        self.client.get(
            "/api/v3/purl/base?q=type=rpm&total=true",
            name="/api/v3/purl/base?q=type=rpm&total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_base_by_ns(self) -> None:
        self.client.get(
            "/api/v3/purl/base?q=namespace=redhat&total=true",
            name="/api/v3/purl/base?q=namespace=redhat&total=true",
        )

    @tag("v3", "purl", "list")
    @task
    def list_purl_base_sorted(self) -> None:
        self.client.get(
            "/api/v3/purl/base?sort=name:asc&total=true",
            name="/api/v3/purl/base?sort=name:asc&total=true",
        )

    # -- Product / Organization -----------------------------------------

    @tag("v3", "product", "list")
    @task
    def list_product(self) -> None:
        self.client.get(
            "/api/v3/product?total=true",
            name="/api/v3/product?total=true",
        )

    @tag("v3", "product", "list")
    @task
    def list_product_by_name(self) -> None:
        self.client.get(
            "/api/v3/product?q=name~openshift&total=true",
            name="/api/v3/product?q=name~openshift&total=true",
        )

    @tag("v3", "product", "list")
    @task
    def list_product_sorted(self) -> None:
        self.client.get(
            "/api/v3/product?sort=name:asc&total=true",
            name="/api/v3/product?sort=name:asc&total=true",
        )

    @tag("v3", "organization", "list")
    @task
    def list_organization(self) -> None:
        self.client.get(
            "/api/v3/organization?total=true",
            name="/api/v3/organization?total=true",
        )

    @tag("v3", "organization", "list")
    @task
    def list_organization_sorted(self) -> None:
        self.client.get(
            "/api/v3/organization?sort=name:asc&total=true",
            name="/api/v3/organization?sort=name:asc&total=true",
        )

    # -- Importer / License / Weakness ----------------------------------

    @tag("v3", "importer", "list")
    @task
    def list_importer(self) -> None:
        self.client.get(
            "/api/v3/importer?total=true",
            name="/api/v3/importer?total=true",
        )

    @tag("v3", "license", "list")
    @task
    def list_license(self) -> None:
        self.client.get(
            "/api/v3/license?total=true",
            name="/api/v3/license?total=true",
        )

    @tag("v3", "license", "list")
    @task
    def list_license_sorted(self) -> None:
        self.client.get(
            "/api/v3/license?limit=10&offset=0&q=&sort=license:asc&total=true",
            name="/api/v3/license?limit=10&sort=license:asc&total=true",
        )

    @tag("v3", "license", "list")
    @task
    def list_spdx_license(self) -> None:
        self.client.get(
            "/api/v3/license/spdx/license?total=true",
            name="/api/v3/license/spdx/license?total=true",
        )

    @tag("v3", "weakness", "list")
    @task
    def list_weakness(self) -> None:
        self.client.get(
            "/api/v3/weakness?total=true",
            name="/api/v3/weakness?total=true",
        )

    @tag("v3", "weakness", "list")
    @task
    def list_weakness_by_desc(self) -> None:
        self.client.get(
            "/api/v3/weakness?q=description~injection&total=true",
            name="/api/v3/weakness?q=description~injection&total=true",
        )

    @tag("v3", "weakness", "list")
    @task
    def list_weakness_sorted(self) -> None:
        self.client.get(
            "/api/v3/weakness?sort=id:asc&total=true",
            name="/api/v3/weakness?sort=id:asc&total=true",
        )

    # -- SBOM groups ----------------------------------------------------

    @tag("v3", "group", "list")
    @task
    def list_sbom_group(self) -> None:
        self.client.get(
            "/api/v3/group/sbom?total=true",
            name="/api/v3/group/sbom?total=true",
        )

    @tag("v3", "group", "list")
    @task
    def list_sbom_group_totals(self) -> None:
        self.client.get(
            "/api/v3/group/sbom?totals=true&total=true",
            name="/api/v3/group/sbom?totals=true&total=true",
        )

    @tag("v3", "group", "list")
    @task
    def list_sbom_group_parents(self) -> None:
        self.client.get(
            "/api/v3/group/sbom?parents=resolve&total=true",
            name="/api/v3/group/sbom?parents=resolve&total=true",
        )

    # -- Well-known / misc ----------------------------------------------

    @tag("v3", "misc")
    @task
    def well_known(self) -> None:
        self.client.get(
            "/.well-known/trustify",
            name="/.well-known/trustify",
        )

    @tag("v3", "misc")
    @task
    def post_extract_sbom_purls(self) -> None:
        payload = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "locust-test",
            "documentNamespace": "https://example.com/locust",
            "packages": [],
        }
        self.client.post(
            "/api/v3/ui/extract-sbom-purls",
            json=payload,
            name="post_extract_sbom_purls",
        )

    @tag("v3", "vulnerability")
    @task
    def post_vulnerability_analyze_v3(self) -> None:
        self.client.post(
            "/api/v3/vulnerability/analyze",
            json={"purls": ["pkg:rpm/redhat/openssl@3.0.0"]},
            name="post_vulnerability_analyze_v3",
        )

    # -- Scenario-driven detail endpoints -------------------------------

    @tag("v3", "advisory", "detail")
    @task
    def get_advisory(self) -> None:
        if not SCENARIO.get_advisory:
            return
        uid = SCENARIO.get_advisory
        with self.client.get(
            f"/api/v3/advisory/urn:uuid:{uid}",
            name=f"get_advisory[{uid[:12]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "advisory", "detail")
    @task
    def download_advisory(self) -> None:
        if not SCENARIO.download_advisory:
            return
        uid = SCENARIO.download_advisory
        with self.client.get(
            f"/api/v3/advisory/urn:uuid:{uid}/download",
            name=f"download_advisory[{uid[:12]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "sbom", "detail")
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

    @tag("v3", "vulnerability", "detail")
    @task
    def get_vulnerability(self) -> None:
        if not SCENARIO.get_vulnerability:
            return
        vid = SCENARIO.get_vulnerability
        with self.client.get(
            f"/api/v3/vulnerability/{quote(vid, safe='')}",
            name=f"get_vulnerability[{vid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "vulnerability", "detail")
    @task
    def get_vulnerability_scores(self) -> None:
        if not SCENARIO.get_vulnerability:
            return
        vid = SCENARIO.get_vulnerability
        with self.client.get(
            f"/api/v3/vulnerability/{quote(vid, safe='')}?scores=true",
            name=f"get_vulnerability_scores[{vid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "vulnerability")
    @task
    def post_vulnerability_analyze(self) -> None:
        if not SCENARIO.analyze_purl:
            return
        purl = SCENARIO.analyze_purl
        with self.client.post(
            "/api/v3/vulnerability/analyze",
            json={"purls": [purl]},
            name=f"post_vulnerability_analyze[{purl[:20]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "purl", "detail")
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

    @tag("v3", "purl", "detail")
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

    @tag("v3", "purl")
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

    @tag("v3", "product", "detail")
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

    @tag("v3", "organization", "detail")
    @task
    def get_organization(self) -> None:
        if not SCENARIO.get_organization:
            return
        oid = SCENARIO.get_organization
        with self.client.get(
            f"/api/v3/organization/{quote(oid, safe='')}",
            name=f"get_organization[{oid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "importer", "detail")
    @task
    def get_importer(self) -> None:
        if not SCENARIO.get_importer:
            return
        name = SCENARIO.get_importer
        with self.client.get(
            f"/api/v3/importer/{quote(name, safe='')}",
            name=f"get_importer[{name}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "importer", "detail")
    @task
    def get_importer_report(self) -> None:
        if not SCENARIO.get_importer:
            return
        name = SCENARIO.get_importer
        with self.client.get(
            f"/api/v3/importer/{quote(name, safe='')}/report",
            name=f"get_importer_report[{name}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "license", "detail")
    @task
    def get_spdx_license(self) -> None:
        if not SCENARIO.get_spdx_license:
            return
        lid = SCENARIO.get_spdx_license
        with self.client.get(
            f"/api/v3/license/spdx/license/{quote(lid, safe='')}",
            name=f"get_spdx_license[{lid}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v3", "weakness", "detail")
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

    @tag("v3", "group", "detail")
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

    @tag("v3", "group", "detail")
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

