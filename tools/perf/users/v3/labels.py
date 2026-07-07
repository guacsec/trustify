"""Label mutation users -- advisory and SBOM label PUT/PATCH (v3).

AdvisoryLabelUserV3 discovers a random advisory then PUT/PATCH labels.
SBOMLabelUserV3 mutates labels on scenario-provided SBOM IDs.
"""

from __future__ import annotations

import random
from urllib.parse import quote

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

from scenario import SCENARIO


class AdvisoryLabelUserV3(AuthenticatedHttpUser):
    """Finds random advisories and mutates their v3 labels."""

    weight = 2
    wait_time = WAIT_TIME

    def on_start(self) -> None:
        super().on_start()
        self._advisory_uuid: str | None = None

    def _find_random_advisory(self) -> str | None:
        """Fetch a random advisory UUID from the list endpoint."""
        with self.client.get(
            "/api/v3/advisory?limit=1",
            name="find_random_advisory",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
                return None
            try:
                data = resp.json()
                total = data.get("total") or 0
                if total == 0:
                    resp.failure("no advisories in database")
                    return None
            except Exception as exc:
                resp.failure(str(exc))
                return None

        offset = random.randint(0, max(total - 1, 0))  # noqa: S311
        with self.client.get(
            f"/api/v3/advisory?offset={offset}&limit=1",
            name="find_random_advisory",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status {resp.status_code}")
                return None
            try:
                items = resp.json().get("items", [])
                if not items:
                    resp.failure("empty result")
                    return None
                return items[0].get("uuid") or items[0].get("id")
            except Exception as exc:
                resp.failure(str(exc))
                return None

    @tag("v3", "advisory", "labels")
    @task
    def list_advisory_labels(self) -> None:
        self.client.get(
            "/api/v3/advisory-labels?filter_text=type&limit=1000",
            name="list_advisory_labels",
        )

    @tag("v3", "advisory", "labels")
    @task(3)
    def put_and_patch_advisory_labels(self) -> None:
        uid = self._find_random_advisory()
        if not uid:
            return

        put_body = {
            "source": "load-test-put",
            "load-test": "true",
            "foo": "bar",
        }
        self.client.put(
            f"/api/v3/advisory/urn:uuid:{uid}/label",
            json=put_body,
            name="put_advisory_labels",
        )

        patch_body = {
            "source": "load-test-patch",
            "load-test": "true",
            "foo": "baz",
        }
        self.client.patch(
            f"/api/v3/advisory/urn:uuid:{uid}/label",
            json=patch_body,
            name="patch_advisory_labels",
        )


class SBOMLabelUserV3(AuthenticatedHttpUser):
    """Mutates SBOM labels using scenario-provided SBOM IDs (v3)."""

    weight = 2
    wait_time = WAIT_TIME

    @tag("v3", "sbom", "labels")
    @task
    def put_sbom_labels(self) -> None:
        if not SCENARIO.get_sbom:
            return
        key = SCENARIO.get_sbom
        body = {"source": "load-test", "load-test": "true"}
        self.client.put(
            f"/api/v3/sbom/{quote(key, safe='')}/label",
            json=body,
            name="put_sbom_labels",
        )

    @tag("v3", "sbom", "labels")
    @task
    def patch_sbom_labels(self) -> None:
        if not SCENARIO.get_sbom:
            return
        key = SCENARIO.get_sbom
        body = {"source": "load-test-patch", "load-test": "true"}
        self.client.patch(
            f"/api/v3/sbom/{quote(key, safe='')}/label",
            json=body,
            name="patch_sbom_labels",
        )
