"""Conforma (Enterprise Contract) checker plugin.

Validates SBOM data against OPA/Rego policies using the Conforma ``ec``
CLI or its HTTP server mode.

Two integration modes:

1. **CLI mode** (default): Shells out to ``ec validate input`` with a
   JSON file containing Trustify data as the policy input.
2. **Server mode**: POSTs to a running Conforma server at
   ``POST /v1/validate/input``.

Config example::

    {
      "name": "conforma",
      "config": {
        "mode": "cli",
        "ec_binary": "ec",
        "policy": "git::https://github.com/conforma/policy//policy/release",
        "policy_file": "./my-policy.yaml",
        "server_url": "http://localhost:8090",
        "extra_args": ["--ignore-rekor"]
      }
    }

The checker assembles a policy input document from the Trustify data
(SBOM metadata, PURLs, vulnerability analysis, advisories, licenses)
and passes it to Conforma for evaluation.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from checkers import CheckContext, register_checker
from policy import Violation

CHECKER_NAME = "conforma"


class ConformaChecker:
    """Validates Trustify data against Conforma/EC OPA policies."""

    @property
    def name(self) -> str:
        return CHECKER_NAME

    def check(self, ctx: CheckContext, config: dict[str, Any]) -> list[Violation]:
        mode = config.get("mode", "cli")
        policy_input = _build_policy_input(ctx)

        if mode == "server":
            raw_result = _validate_via_server(policy_input, config)
        else:
            raw_result = _validate_via_cli(policy_input, config)

        return _parse_conforma_result(raw_result)


def _build_policy_input(ctx: CheckContext) -> dict[str, Any]:
    """Assemble the JSON document that becomes Conforma's policy input.

    This gives Rego rules access to all Trustify-sourced data under
    a ``trustify`` top-level key, plus standard fields Conforma expects.
    """
    doc: dict[str, Any] = {
        "trustify": {
            "sbom_id": ctx.sbom_id,
            "sbom_name": ctx.sbom_name,
            "purls": ctx.purls,
        },
    }

    if ctx.vuln_analysis is not None:
        doc["trustify"]["vulnerabilities"] = ctx.vuln_analysis

    if ctx.advisories is not None:
        doc["trustify"]["advisories"] = ctx.advisories

    if ctx.license_ids is not None:
        licenses = ctx.license_ids
        if isinstance(licenses, dict):
            licenses = licenses.get("items", licenses.get("licenses", []))
        doc["trustify"]["licenses"] = licenses

    if ctx.sbom_detail is not None:
        doc["trustify"]["sbom"] = ctx.sbom_detail

    return doc


def _validate_via_cli(
    policy_input: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Run ``ec validate input`` as a subprocess."""
    ec_binary = config.get("ec_binary", "ec")
    policy = config.get("policy", "")
    policy_file = config.get("policy_file", "")
    extra_args: list[str] = config.get("extra_args", [])

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False,
    ) as f:
        json.dump(policy_input, f)
        input_path = f.name

    cmd = [ec_binary, "validate", "input"]
    cmd.extend(["--file", input_path])
    cmd.extend(["--output", "json"])

    # Policy source: either a policy spec file or inline policy source.
    if policy_file:
        cmd.extend(["--policy", policy_file])
    elif policy:
        cmd.extend(["--policy", policy])

    # Conforma returns non-zero on policy failure, which is expected.
    cmd.extend(["--strict=false"])
    cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        print(
            f"error: conforma binary '{ec_binary}' not found. "
            "Install it from https://github.com/conforma/cli",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("error: conforma validation timed out after 120s", file=sys.stderr)
        sys.exit(1)
    finally:
        Path(input_path).unlink(missing_ok=True)

    if result.returncode not in (0, 1):
        # 0 = pass, 1 = policy failure, anything else = error
        print(
            f"error: conforma exited with code {result.returncode}\n"
            f"stderr: {result.stderr}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        print(
            f"error: conforma produced invalid JSON output:\n{result.stdout[:500]}",
            file=sys.stderr,
        )
        sys.exit(1)


def _validate_via_server(
    policy_input: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    """POST to a running Conforma HTTP server."""
    import httpx

    server_url = config.get("server_url", "http://localhost:8090")
    url = f"{server_url}/v1/validate/input"

    try:
        with httpx.Client(timeout=120.0) as c:
            r = c.post(url, json=policy_input)
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        print(
            f"error: cannot connect to conforma server at {server_url}. "
            "Start it with: ec validate input --server --server-port 8090",
            file=sys.stderr,
        )
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        print(f"error: conforma server returned {e.response.status_code}", file=sys.stderr)
        sys.exit(1)


def _parse_conforma_result(raw: dict[str, Any]) -> list[Violation]:
    """Convert Conforma's JSON output into gate Violations."""
    violations: list[Violation] = []

    # Conforma output can be a single result or a list of component results.
    components = raw.get("components", [raw]) if raw else []

    for component in components:
        # Each component has success, violations (failures), warnings.
        for failure in component.get("violations", component.get("failures", [])):
            violations.append(_failure_to_violation(failure))

        # Also check the nested "results" structure used by some output formats.
        for result_item in component.get("results", []):
            if not result_item.get("success", True):
                for failure in result_item.get("violations", result_item.get("failures", [])):
                    violations.append(_failure_to_violation(failure))

    return violations


def _failure_to_violation(failure: dict[str, Any]) -> Violation:
    """Map a single Conforma failure entry to a Violation."""
    msg = failure.get("msg", failure.get("message", "Conforma policy violation"))
    title = failure.get("metadata", {}).get("title", "")
    code = failure.get("metadata", {}).get("code", failure.get("code", ""))
    short_name = (
        failure.get("metadata", {}).get("custom", {}).get("short_name", "")
    )

    identifier = code or short_name or "conforma-violation"
    display_msg = f"{title}: {msg}" if title else msg

    # Map Conforma severity to gate severity levels.
    # Conforma failures are implicitly "high" unless annotated otherwise.
    severity = failure.get("severity", "high").lower()

    return Violation(
        kind="conforma",
        severity=severity,
        identifier=identifier,
        message=display_msg,
        checker=CHECKER_NAME,
    )


register_checker(CHECKER_NAME, ConformaChecker)
