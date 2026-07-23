"""Gate configuration loaded from environment variables."""

import os


TRUSTIFY_URL = os.environ.get("TRUSTIFY_URL", "http://localhost:8080")
TRUSTIFY_TOKEN = os.environ.get("TRUSTIFY_TOKEN", "")
