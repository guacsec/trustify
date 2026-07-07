"""RestAPIUserV2 -- main REST API v2 load test (weight 10).

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


class RestAPIUserV2(AuthenticatedHttpUser):
    """Exercises the trustify v2 REST API with realistic query patterns."""

    weight = 10
    wait_time = WAIT_TIME

    # -- Advisory list endpoints ----------------------------------------

    @tag("v2", "advisory", "list")
    @task
    def list_advisory(self) -> None:
        self.client.get("/api/v2/advisory", name="/api/v2/advisory")

    @tag("v2", "advisory", "list")
    @task
    def list_advisory_paginated(self) -> None:
        self.client.get(
            "/api/v2/advisory?offset=100&limit=10",
            name="/api/v2/advisory?offset=100&limit=10",
        )

    @tag("v2", "advisory", "list")
    @task
    def list_advisory_by_identifier(self) -> None:
        self.client.get(
            "/api/v2/advisory?q=identifier%3dCVE-2022-0981",
            name="/api/v2/advisory?q=identifier=CVE-2022-0981",
        )

    @tag("v2", "advisory", "list")
    @task
    def list_advisory_by_cve_prefix(self) -> None:
        self.client.get(
            "/api/v2/advisory?q=CVE-2021-",
            name="/api/v2/advisory?q=CVE-2021-",
        )

    @tag("v2", "advisory", "list")
    @task
    def list_advisory_by_title(self) -> None:
        self.client.get(
            "/api/v2/advisory?q=title~openssl",
            name="/api/v2/advisory?q=title~openssl",
        )

    @tag("v2", "advisory", "list")
    @task
    def list_advisory_by_modified(self) -> None:
        self.client.get(
            "/api/v2/advisory?q=modified>3 days ago",
            name="/api/v2/advisory?q=modified>3 days ago",
        )

    @tag("v2", "advisory", "list")
    @task
    def list_advisory_sorted(self) -> None:
        self.client.get(
            "/api/v2/advisory?sort=modified:desc",
            name="/api/v2/advisory?sort=modified:desc",
        )

    @tag("v2", "advisory", "list")
    @task
    def list_advisory_deprecated(self) -> None:
        self.client.get(
            "/api/v2/advisory?deprecated=Consider",
            name="/api/v2/advisory?deprecated=Consider",
        )

    # -- Vulnerability list endpoints -----------------------------------

    @tag("v2", "vulnerability", "list")
    @task
    def list_vulnerability(self) -> None:
        self.client.get(
            "/api/v2/vulnerability",
            name="/api/v2/vulnerability",
        )

    @tag("v2", "vulnerability", "list")
    @task
    def list_vulnerability_paginated(self) -> None:
        self.client.get(
            "/api/v2/vulnerability?offset=100&limit=10",
            name="/api/v2/vulnerability?offset=100&limit=10",
        )

    @tag("v2", "vulnerability", "list")
    @task
    def list_vulnerability_high(self) -> None:
        self.client.get(
            "/api/v2/vulnerability?q=base_severity=high",
            name="/api/v2/vulnerability?q=base_severity=high",
        )

    @tag("v2", "vulnerability", "list")
    @task
    def list_vulnerability_score(self) -> None:
        self.client.get(
            "/api/v2/vulnerability?q=base_score>=7.0",
            name="/api/v2/vulnerability?q=base_score>=7.0",
        )

    @tag("v2", "vulnerability", "list")
    @task
    def list_vulnerability_cwe(self) -> None:
        self.client.get(
            "/api/v2/vulnerability?q=cwes=CWE-79",
            name="/api/v2/vulnerability?q=cwes=CWE-79",
        )

    @tag("v2", "vulnerability", "list")
    @task
    def list_vulnerability_sorted(self) -> None:
        self.client.get(
            "/api/v2/vulnerability?sort=base_score:desc",
            name="/api/v2/vulnerability?sort=base_score:desc",
        )

    # -- SBOM list endpoints --------------------------------------------

    @tag("v2", "sbom", "list")
    @task(2)
    def list_sbom(self) -> None:
        self.client.get("/api/v2/sbom", name="/api/v2/sbom")

    @tag("v2", "sbom", "list")
    @task(2)
    def list_sbom_paginated(self) -> None:
        self.client.get(
            "/api/v2/sbom?offset=100&limit=10",
            name="/api/v2/sbom?offset=100&limit=10",
        )

    @tag("v2", "sbom", "list")
    @task
    def list_sbom_by_name(self) -> None:
        self.client.get(
            "/api/v2/sbom?q=name~redhat",
            name="/api/v2/sbom?q=name~redhat",
        )

    @tag("v2", "sbom", "list")
    @task
    def list_sbom_by_published(self) -> None:
        self.client.get(
            "/api/v2/sbom?q=published>2024-01-01",
            name="/api/v2/sbom?q=published>2024-01-01",
        )

    @tag("v2", "sbom", "list")
    @task
    def list_sbom_sorted(self) -> None:
        self.client.get(
            "/api/v2/sbom?sort=ingested:desc",
            name="/api/v2/sbom?sort=ingested:desc",
        )

    @tag("v2", "sbom", "list")
    @task
    def list_sbom_by_label(self) -> None:
        self.client.get(
            "/api/v2/sbom?q=label:type=product",
            name="/api/v2/sbom?q=label:type=product",
        )

    @tag("v2", "sbom", "list")
    @task
    def list_sbom_labels(self) -> None:
        self.client.get(
            "/api/v2/sbom-labels",
            name="/api/v2/sbom-labels",
        )

    # -- PURL list endpoints --------------------------------------------

    @tag("v2", "purl", "list")
    @task
    def list_purl(self) -> None:
        self.client.get("/api/v2/purl", name="/api/v2/purl")

    @tag("v2", "purl", "list")
    @task
    def list_purl_paginated(self) -> None:
        self.client.get(
            "/api/v2/purl?offset=100&limit=10",
            name="/api/v2/purl?offset=100&limit=10",
        )

    @tag("v2", "purl", "list")
    @task
    def list_purl_by_name(self) -> None:
        self.client.get(
            "/api/v2/purl?q=curl",
            name="/api/v2/purl?q=curl",
        )

    @tag("v2", "purl", "list")
    @task
    def list_purl_by_exact_name(self) -> None:
        self.client.get(
            "/api/v2/purl?q=name=curl",
            name="/api/v2/purl?q=name=curl",
        )

    @tag("v2", "purl", "list")
    @task
    def list_purl_by_type(self) -> None:
        self.client.get(
            "/api/v2/purl?q=purl:ty=rpm",
            name="/api/v2/purl?q=purl:ty=rpm",
        )

    @tag("v2", "purl", "list")
    @task
    def list_purl_by_namespace(self) -> None:
        self.client.get(
            "/api/v2/purl?q=purl:namespace=redhat",
            name="/api/v2/purl?q=purl:namespace=redhat",
        )

    @tag("v2", "purl", "list")
    @task
    def list_purl_sorted(self) -> None:
        self.client.get(
            "/api/v2/purl?sort=purl:name:asc",
            name="/api/v2/purl?sort=purl:name:asc",
        )

    # -- PURL base endpoints --------------------------------------------

    @tag("v2", "purl", "list")
    @task
    def list_purl_base(self) -> None:
        self.client.get("/api/v2/purl/base", name="/api/v2/purl/base")

    @tag("v2", "purl", "list")
    @task
    def list_purl_base_by_type(self) -> None:
        self.client.get(
            "/api/v2/purl/base?q=type=rpm",
            name="/api/v2/purl/base?q=type=rpm",
        )

    @tag("v2", "purl", "list")
    @task
    def list_purl_base_by_ns(self) -> None:
        self.client.get(
            "/api/v2/purl/base?q=namespace=redhat",
            name="/api/v2/purl/base?q=namespace=redhat",
        )

    @tag("v2", "purl", "list")
    @task
    def list_purl_base_sorted(self) -> None:
        self.client.get(
            "/api/v2/purl/base?sort=name:asc",
            name="/api/v2/purl/base?sort=name:asc",
        )

    # -- Product / Organization -----------------------------------------

    @tag("v2", "product", "list")
    @task
    def list_product(self) -> None:
        self.client.get("/api/v2/product", name="/api/v2/product")

    @tag("v2", "product", "list")
    @task
    def list_product_by_name(self) -> None:
        self.client.get(
            "/api/v2/product?q=name~openshift",
            name="/api/v2/product?q=name~openshift",
        )

    @tag("v2", "product", "list")
    @task
    def list_product_sorted(self) -> None:
        self.client.get(
            "/api/v2/product?sort=name:asc",
            name="/api/v2/product?sort=name:asc",
        )

    @tag("v2", "organization", "list")
    @task
    def list_organization(self) -> None:
        self.client.get(
            "/api/v2/organization",
            name="/api/v2/organization",
        )

    @tag("v2", "organization", "list")
    @task
    def list_organization_sorted(self) -> None:
        self.client.get(
            "/api/v2/organization?sort=name:asc",
            name="/api/v2/organization?sort=name:asc",
        )

    # -- Importer / License / Weakness ----------------------------------
    #
    # NOTE: v3 has these additional endpoints not present in v2:
    #   - /api/v3/license (list_license) -- v2 only has spdx/license
    #   - /api/v3/group/sbom (list_sbom_group, totals, parents)
    #   - /api/v3/ui/extract-sbom-purls (post_extract_sbom_purls)
    #   - /api/v3/vulnerability/analyze with hardcoded PURL

    @tag("v2", "importer", "list")
    @task
    def list_importer(self) -> None:
        self.client.get("/api/v2/importer", name="/api/v2/importer")

    @tag("v2", "license", "list")
    @task
    def list_spdx_license(self) -> None:
        self.client.get(
            "/api/v2/license/spdx/license",
            name="/api/v2/license/spdx/license",
        )

    @tag("v2", "weakness", "list")
    @task
    def list_weakness(self) -> None:
        self.client.get("/api/v2/weakness", name="/api/v2/weakness")

    @tag("v2", "weakness", "list")
    @task
    def list_weakness_by_desc(self) -> None:
        self.client.get(
            "/api/v2/weakness?q=description~injection",
            name="/api/v2/weakness?q=description~injection",
        )

    @tag("v2", "weakness", "list")
    @task
    def list_weakness_sorted(self) -> None:
        self.client.get(
            "/api/v2/weakness?sort=id:asc",
            name="/api/v2/weakness?sort=id:asc",
        )

    # -- Well-known / misc ----------------------------------------------

    @tag("v2", "misc")
    @task
    def well_known(self) -> None:
        self.client.get(
            "/.well-known/trustify",
            name="/.well-known/trustify",
        )

    # -- Scenario-driven detail endpoints -------------------------------

    @tag("v2", "advisory", "detail")
    @task
    def get_advisory(self) -> None:
        if not SCENARIO.get_advisory:
            return
        uid = SCENARIO.get_advisory
        with self.client.get(
            f"/api/v2/advisory/urn:uuid:{uid}",
            name=f"v2/get_advisory[{uid[:12]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "advisory", "detail")
    @task
    def download_advisory(self) -> None:
        if not SCENARIO.download_advisory:
            return
        uid = SCENARIO.download_advisory
        with self.client.get(
            f"/api/v2/advisory/urn:uuid:{uid}/download",
            name=f"v2/download_advisory[{uid[:12]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def get_sbom(self) -> None:
        if not SCENARIO.get_sbom:
            return
        key = SCENARIO.get_sbom
        with self.client.get(
            f"/api/v2/sbom/{quote(key, safe='')}",
            name=f"v2/get_sbom[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def get_sbom_advisories(self) -> None:
        if not SCENARIO.get_sbom_advisories:
            return
        key = SCENARIO.get_sbom_advisories
        with self.client.get(
            f"/api/v2/sbom/{quote(key, safe='')}/advisory",
            name=f"v2/get_sbom_advisories[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def get_sbom_packages(self) -> None:
        if not SCENARIO.get_sbom_packages:
            return
        key = SCENARIO.get_sbom_packages
        with self.client.get(
            f"/api/v2/sbom/{quote(key, safe='')}/packages",
            name=f"v2/get_sbom_packages[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def get_sbom_related(self) -> None:
        if not SCENARIO.get_sbom_related:
            return
        key = SCENARIO.get_sbom_related
        with self.client.get(
            f"/api/v2/sbom/{quote(key, safe='')}/related",
            name=f"v2/get_sbom_related[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def get_sbom_license_ids(self) -> None:
        if not SCENARIO.sbom_license_ids:
            return
        key = SCENARIO.sbom_license_ids
        with self.client.get(
            f"/api/v2/sbom/{quote(key, safe='')}/all-license-ids",
            name=f"v2/get_sbom_license_ids[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def download_sbom(self) -> None:
        if not SCENARIO.download_sbom:
            return
        key = SCENARIO.download_sbom
        with self.client.get(
            f"/api/v2/sbom/{quote(key, safe='')}/download",
            name=f"v2/download_sbom[{key[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def get_sbom_license_export(self) -> None:
        if not SCENARIO.get_sbom_license_export:
            return
        sid = SCENARIO.get_sbom_license_export
        with self.client.get(
            f"/api/v2/sbom/{quote(sid, safe='')}/license-export",
            name=f"v2/get_sbom_license_export[{sid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def sbom_by_package(self) -> None:
        if not SCENARIO.sbom_by_package:
            return
        purl = SCENARIO.sbom_by_package
        with self.client.get(
            f"/api/v2/sbom/by-package?purl={quote(purl, safe='')}",
            name=f"v2/sbom_by_package[{purl[:20]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "sbom", "detail")
    @task
    def count_sbom_by_package(self) -> None:
        if not SCENARIO.count_sbom_by_package:
            return
        purl = SCENARIO.count_sbom_by_package
        with self.client.get(
            "/api/v2/sbom/count-by-package",
            json=[{"purl": purl}],
            name=f"v2/count_sbom_by_package[{purl[:20]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "vulnerability", "detail")
    @task
    def get_vulnerability(self) -> None:
        if not SCENARIO.get_vulnerability:
            return
        vid = SCENARIO.get_vulnerability
        with self.client.get(
            f"/api/v2/vulnerability/{quote(vid, safe='')}",
            name=f"v2/get_vulnerability[{vid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "vulnerability", "detail")
    @task
    def get_vulnerability_scores(self) -> None:
        if not SCENARIO.get_vulnerability:
            return
        vid = SCENARIO.get_vulnerability
        with self.client.get(
            f"/api/v2/vulnerability/{quote(vid, safe='')}?scores=true",
            name=f"v2/get_vulnerability_scores[{vid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "vulnerability")
    @task
    def post_vulnerability_analyze(self) -> None:
        if not SCENARIO.analyze_purl:
            return
        purl = SCENARIO.analyze_purl
        with self.client.post(
            "/api/v2/vulnerability/analyze",
            json={"purls": [purl]},
            name=f"v2/post_vulnerability_analyze[{purl[:20]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "purl", "detail")
    @task
    def get_purl_details(self) -> None:
        if not SCENARIO.get_purl_details:
            return
        pid = SCENARIO.get_purl_details
        with self.client.get(
            f"/api/v2/purl/{quote(pid, safe='')}",
            name=f"v2/get_purl_details[{pid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "purl", "detail")
    @task
    def get_base_purl(self) -> None:
        if not SCENARIO.get_base_purl:
            return
        key = SCENARIO.get_base_purl
        with self.client.get(
            f"/api/v2/purl/base/{quote(key, safe='')}",
            name=f"v2/get_base_purl[{key[:20]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "purl")
    @task(3)
    def get_recommendations(self) -> None:
        if not SCENARIO.get_recommendations:
            return
        batch = SCENARIO.get_recommendations[:25]
        with self.client.post(
            "/api/v2/purl/recommend",
            json={"purls": batch},
            name=f"v2/get_recommendations[batch={len(batch)}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "product", "detail")
    @task
    def get_product(self) -> None:
        if not SCENARIO.get_product:
            return
        pid = SCENARIO.get_product
        with self.client.get(
            f"/api/v2/product/{quote(pid, safe='')}",
            name=f"v2/get_product[{pid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "organization", "detail")
    @task
    def get_organization(self) -> None:
        if not SCENARIO.get_organization:
            return
        oid = SCENARIO.get_organization
        with self.client.get(
            f"/api/v2/organization/{quote(oid, safe='')}",
            name=f"v2/get_organization[{oid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "importer", "detail")
    @task
    def get_importer(self) -> None:
        if not SCENARIO.get_importer:
            return
        name = SCENARIO.get_importer
        with self.client.get(
            f"/api/v2/importer/{quote(name, safe='')}",
            name=f"v2/get_importer[{name}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "importer", "detail")
    @task
    def get_importer_report(self) -> None:
        if not SCENARIO.get_importer:
            return
        name = SCENARIO.get_importer
        with self.client.get(
            f"/api/v2/importer/{quote(name, safe='')}/report",
            name=f"v2/get_importer_report[{name}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "license", "detail")
    @task
    def get_spdx_license(self) -> None:
        if not SCENARIO.get_spdx_license:
            return
        lid = SCENARIO.get_spdx_license
        with self.client.get(
            f"/api/v2/license/spdx/license/{quote(lid, safe='')}",
            name=f"v2/get_spdx_license[{lid}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "weakness", "detail")
    @task
    def get_weakness(self) -> None:
        if not SCENARIO.get_weakness:
            return
        wid = SCENARIO.get_weakness
        with self.client.get(
            f"/api/v2/weakness/{quote(wid, safe='')}",
            name=f"v2/get_weakness[{wid}]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "group", "detail")
    @task
    def get_sbom_group(self) -> None:
        if not SCENARIO.get_sbom_group:
            return
        gid = SCENARIO.get_sbom_group
        with self.client.get(
            f"/api/v2/group/sbom/{quote(gid, safe='')}",
            name=f"v2/get_sbom_group[{gid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")

    @tag("v2", "group", "detail")
    @task
    def get_sbom_group_assignments(self) -> None:
        if not SCENARIO.get_sbom_group:
            return
        gid = SCENARIO.get_sbom_group
        with self.client.get(
            f"/api/v2/group/sbom-assignment/{quote(gid, safe='')}",
            name=f"v2/get_sbom_group_assignments[{gid[:16]}...]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
