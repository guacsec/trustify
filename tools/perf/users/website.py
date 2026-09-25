"""WebsiteUser -- simulates UI page browsing (weight 1).

Hits the main HTML pages a real user would navigate through.
"""

from __future__ import annotations

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser


class WebsiteUser(AuthenticatedHttpUser):
    """Simulates a user browsing the trustify web UI."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("website")
    @task
    def index(self) -> None:
        self.client.get("/", name="/")

    @tag("website")
    @task
    def openapi(self) -> None:
        self.client.get("/openapi/", name="/openapi/")

    @tag("website")
    @task
    def sboms(self) -> None:
        self.client.get("/sboms", name="/sboms")

    @tag("website")
    @task
    def packages(self) -> None:
        self.client.get("/packages", name="/packages")

    @tag("website")
    @task
    def advisories(self) -> None:
        self.client.get("/advisories", name="/advisories")

    @tag("website")
    @task
    def importers(self) -> None:
        self.client.get("/importers", name="/importers")
