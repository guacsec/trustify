"""Trustify Locust load tests -- main entry point.

Imports user classes based on the TOOLS_PERF_API_VERSION environment variable so
Locust discovers them automatically.

Run from the ``tools/perf/`` directory:

    uv run locust --host http://localhost:8080 -u 10

Or headless:

    uv run locust --host http://localhost:8080 -u 10 -r 2 -t 5m --headless

Select API version (default: v3):

    TOOLS_PERF_API_VERSION=v2 uv run locust --host http://localhost:8080 -u 10
    TOOLS_PERF_API_VERSION=all uv run locust --host http://localhost:8080 -u 10

Filter by tag:

    uv run locust --host http://localhost:8080 -u 10 --tags advisory

Environment variables:

    TOOLS_PERF_API_VERSION     Which API version to test: v2, v3 (default), or all.
    TOOLS_PERF_WAIT_TIME_FROM  Min seconds between requests per user (default: 1).
    TOOLS_PERF_WAIT_TIME_TO    Max seconds between requests per user (default: 3).
                               Set both to 0 for no delay (max throughput).
    TOOLS_PERF_SCENARIO_FILE   Path to a JSON5 scenario file with pre-computed IDs.
                               If unset, scenario-dependent tests are skipped.

    ISSUER_URL                 OIDC issuer URL (required unless AUTH_DISABLED).
    CLIENT_ID                  OAuth2 client ID (required unless AUTH_DISABLED).
    CLIENT_SECRET              OAuth2 client secret (required unless AUTH_DISABLED).
    OIDC_REFRESH_BEFORE        Seconds before expiry to refresh token (default: 30).
    AUTH_DISABLED              Set to "true" or "1" to skip OIDC auth.

See auth.py, scenario.py, and the users/ modules for details.
"""

import os

TOOLS_PERF_API_VERSION = os.environ.get("TOOLS_PERF_API_VERSION", "v3")

# Website tests are version-agnostic -- always loaded.
from users.website import WebsiteUser  # noqa: F401, E402

if TOOLS_PERF_API_VERSION in ("v3", "all"):
    from users.v3.analysis import AnalysisUserV3  # noqa: F401
    from users.v3.labels import (  # noqa: F401
        AdvisoryLabelUserV3,
        SBOMLabelUserV3,
    )
    from users.v3.rest_api import RestAPIUserV3  # noqa: F401
    from users.v3.rest_api_slow import RestAPIUserSlowV3  # noqa: F401

if TOOLS_PERF_API_VERSION in ("v2", "all"):
    from users.v2.analysis import AnalysisUserV2  # noqa: F401
    from users.v2.rest_api import RestAPIUserV2  # noqa: F401
    from users.v2.rest_api_slow import RestAPIUserSlowV2  # noqa: F401
