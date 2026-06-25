"""WebsiteUser -- simulates UI page browsing (weight 1).

Hits the main HTML pages a real user would navigate through.
"""

from __future__ import annotations

from locust import HttpUser, tag, task
from config import WAIT_TIME


class WebsiteUser(HttpUser):
    """Simulates a user browsing the trustify web UI."""

    weight = 1
    wait_time = WAIT_TIME

    @tag("website")
    @task
    def index(self) -> None:
        self.client.get("/", name="website_index")

    @tag("website")
    @task
    def openapi(self) -> None:
        self.client.get("/openapi/", name="website_openapi")

    @tag("website")
    @task
    def sboms(self) -> None:
        self.client.get("/sboms", name="website_sboms")

    @tag("website")
    @task
    def packages(self) -> None:
        self.client.get("/packages", name="website_packages")

    @tag("website")
    @task
    def advisories(self) -> None:
        self.client.get("/advisories", name="website_advisories")

    @tag("website")
    @task
    def importers(self) -> None:
        self.client.get("/importers", name="website_importers")
