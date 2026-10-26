"""Discover and select workloads for capabilities exposed by Trustify."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

log = logging.getLogger(__name__)

DISCOVERY_PATH = "/.well-known/trustify"
DISCOVERY_TIMEOUT = 10
MAX_DISCOVERY_BYTES = 1024 * 1024
MAX_CAPABILITIES = 100
MAX_CAPABILITY_LENGTH = 256


class CapabilityDiscoveryError(RuntimeError):
    """The target's capability document could not be read or validated."""


def discover_capabilities(host: str) -> frozenset[str]:
    """Fetch and validate the target's advertised capabilities."""
    if not host:
        raise CapabilityDiscoveryError("target host is not configured")

    url = f"{host.rstrip('/')}{DISCOVERY_PATH}"
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=DISCOVERY_TIMEOUT) as response:  # noqa: S310
            body = response.read(MAX_DISCOVERY_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        raise CapabilityDiscoveryError(
            "could not fetch the Trustify capability document"
        ) from exc

    if len(body) > MAX_DISCOVERY_BYTES:
        raise CapabilityDiscoveryError("Trustify capability document is too large")

    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CapabilityDiscoveryError(
            "Trustify capability document is not valid JSON"
        ) from exc

    if not isinstance(document, dict):
        raise CapabilityDiscoveryError(
            "Trustify capability document is not an object"
        )

    raw_capabilities = document.get("capabilities")
    if not isinstance(raw_capabilities, list):
        raise CapabilityDiscoveryError(
            "Trustify capability document has no capabilities list"
        )
    if len(raw_capabilities) > MAX_CAPABILITIES:
        raise CapabilityDiscoveryError("Trustify capability list is too large")
    if any(
        not isinstance(capability, str)
        or not capability
        or len(capability) > MAX_CAPABILITY_LENGTH
        for capability in raw_capabilities
    ):
        raise CapabilityDiscoveryError(
            "Trustify capability list contains an invalid entry"
        )

    return frozenset(raw_capabilities)


def filter_user_classes(environment: Any, capabilities: frozenset[str]) -> None:
    """Remove user classes whose required capability is not advertised."""
    unavailable: set[type[Any]] = set()
    for user_class in environment.user_classes:
        required = getattr(user_class, "required_capability", None)
        if required and required not in capabilities:
            unavailable.add(user_class)

    if not unavailable:
        return

    environment.user_classes[:] = [
        user_class
        for user_class in environment.user_classes
        if user_class not in unavailable
    ]

    if environment.available_user_classes is not None:
        unavailable_names = {
            user_class.__name__ for user_class in unavailable
        }
        for name in unavailable_names:
            environment.available_user_classes.pop(name, None)
            if environment.available_user_tasks is not None:
                environment.available_user_tasks.pop(name, None)

    for user_class in sorted(unavailable, key=lambda item: item.__name__):
        required = getattr(user_class, "required_capability")
        log.info(
            "Skipping %s: capability %r is unavailable",
            user_class.__name__,
            required,
        )


def _check_required_capabilities(host: str, required: list[str]) -> int:
    try:
        capabilities = discover_capabilities(host)
    except CapabilityDiscoveryError as exc:
        print(f"Capability discovery failed: {exc}", file=sys.stderr)
        return 1

    missing = sorted(set(required) - capabilities)
    if missing:
        print(f"SKIPPED: unavailable capabilities: {', '.join(missing)}")
        return 2

    print(f"Enabled capabilities: {', '.join(sorted(capabilities))}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--require", action="append", default=[])
    args = parser.parse_args()
    return _check_required_capabilities(args.host, args.require)


if __name__ == "__main__":
    raise SystemExit(main())
