"""Shared configuration for all user classes.

Reads TOOLS_PERF_WAIT_TIME_FROM / TOOLS_PERF_WAIT_TIME_TO from
environment variables and exports a WAIT_TIME callable for use
as HttpUser.wait_time.
"""

import os

from locust import between

WAIT_TIME_FROM = float(os.environ.get("TOOLS_PERF_WAIT_TIME_FROM", "1"))
WAIT_TIME_TO = float(os.environ.get("TOOLS_PERF_WAIT_TIME_TO", "3"))
WAIT_TIME = (
    between(WAIT_TIME_FROM, WAIT_TIME_TO)
    if WAIT_TIME_TO > 0
    else between(0, 0)
)
