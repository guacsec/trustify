"""Trustify Gate -- CI/CD policy gate for the Trustify REST API.

Fetches SBOM, vulnerability, advisory, and license data from a running
Trustify instance, then evaluates it against configurable policy checkers.
Exits non-zero when violations are found.

Usage::

    # Check an SBOM already ingested in Trustify (by name)
    python gate.py check --sbom-name "my-product-1.0"

    # Upload a local SBOM file, then check
    python gate.py check --sbom ./build/sbom.json --upload

    # Check a local SBOM without uploading (extract PURLs, analyze remotely)
    python gate.py check --sbom ./build/sbom.json

    # Use a custom gate config (specifies which checkers to run)
    python gate.py check --sbom ./sbom.json --config gate-config.json

    # Output as JSON / SARIF / JUnit
    python gate.py check --sbom ./sbom.json --format json
"""

import argparse
import sys
from pathlib import Path
from typing import Any

import client
from checkers import CheckContext, available_checkers, get_checker
from formatters import format_result
from policy import GateResult, Violation, default_gate_config, load_gate_config


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="trustify-gate",
        description="CI/CD policy gate for the Trustify REST API",
    )
    sub = parser.add_subparsers(dest="command")

    # -- check ---------------------------------------------------------------
    check_p = sub.add_parser("check", help="Run policy checks against an SBOM")

    sbom_group = check_p.add_mutually_exclusive_group(required=True)
    sbom_group.add_argument(
        "--sbom",
        type=Path,
        help="Path to a local SBOM file (CycloneDX or SPDX JSON)",
    )
    sbom_group.add_argument(
        "--sbom-name",
        help="Name of an SBOM already ingested in Trustify",
    )
    sbom_group.add_argument(
        "--sbom-id",
        help="UUID of an SBOM already ingested in Trustify",
    )

    check_p.add_argument(
        "--upload",
        action="store_true",
        help="Upload the local SBOM to Trustify before checking",
    )
    check_p.add_argument(
        "--config",
        type=Path,
        help="Path to the gate config file (JSON). Default: builtin checker only",
    )
    check_p.add_argument(
        "--format",
        choices=["table", "json", "sarif", "junit"],
        default="table",
        help="Output format (default: table)",
    )
    check_p.add_argument(
        "--output",
        type=Path,
        help="Write output to a file instead of stdout",
    )

    # -- list-checkers -------------------------------------------------------
    sub.add_parser("list-checkers", help="List available checker plugins")

    return parser.parse_args()


def _cmd_list_checkers() -> None:
    names = available_checkers()
    print("Available checkers:")
    for n in names:
        print(f"  - {n}")


def _cmd_check(args: argparse.Namespace) -> None:
    # Load gate config.
    if args.config:
        gate_config = load_gate_config(args.config)
    else:
        gate_config = default_gate_config()

    checker_specs: list[dict[str, Any]] = gate_config.get("checkers", [])
    if not checker_specs:
        print("error: no checkers configured in gate config", file=sys.stderr)
        sys.exit(1)

    # Resolve SBOM: upload, look up, or extract PURLs locally.
    ctx = _build_context(args)

    # Run all configured checkers.
    all_violations: list[Violation] = []
    checkers_run: list[str] = []

    for spec in checker_specs:
        checker_name = spec.get("name", "")
        checker_config = spec.get("config", {})

        try:
            checker_cls = get_checker(checker_name)
        except KeyError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)

        checker = checker_cls()
        print(f"Running checker: {checker.name}", file=sys.stderr)

        violations = checker.check(ctx, checker_config)
        all_violations.extend(violations)
        checkers_run.append(checker.name)

    # Build result.
    result = GateResult(
        passed=len(all_violations) == 0,
        violations=all_violations,
        checkers_run=checkers_run,
    )

    # Output.
    if args.output:
        with open(args.output, "w") as f:
            format_result(result, args.format, out=f)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        format_result(result, args.format)

    # Exit code: 0 = pass, 1 = violations found.
    sys.exit(0 if result.passed else 1)


def _build_context(args: argparse.Namespace) -> CheckContext:
    """Build a CheckContext by resolving the SBOM and fetching data."""
    ctx = CheckContext()

    if args.sbom:
        ctx.sbom_path = args.sbom
        if not args.sbom.exists():
            print(f"error: SBOM file not found: {args.sbom}", file=sys.stderr)
            sys.exit(1)

        if args.upload:
            ctx = _context_from_upload(args.sbom)
        else:
            ctx = _context_from_local(args.sbom)

    elif args.sbom_name:
        ctx = _context_from_name(args.sbom_name)

    elif args.sbom_id:
        ctx = _context_from_id(args.sbom_id)

    return ctx


def _context_from_upload(sbom_path: Path) -> CheckContext:
    """Upload an SBOM to Trustify, then fetch all related data."""
    print(f"Uploading {sbom_path} to Trustify...", file=sys.stderr)

    try:
        result = client.upload_sbom(sbom_path)
    except Exception as e:
        print(f"error: failed to upload SBOM: {e}", file=sys.stderr)
        sys.exit(1)

    sbom_id = result.get("id", result.get("document_id", ""))
    if not sbom_id:
        print("error: upload succeeded but no SBOM ID returned", file=sys.stderr)
        sys.exit(1)

    print(f"SBOM ingested: {sbom_id}", file=sys.stderr)
    return _context_from_id(sbom_id, sbom_path=sbom_path)


def _context_from_name(name: str) -> CheckContext:
    """Look up an SBOM by name and fetch all related data."""
    print(f"Looking up SBOM: {name}", file=sys.stderr)

    sbom = client.find_sbom_by_name(name)
    if not sbom:
        print(f"error: no SBOM found with name '{name}'", file=sys.stderr)
        sys.exit(1)

    sbom_id = sbom.get("id", "")
    return _context_from_id(sbom_id)


def _context_from_id(
    sbom_id: str,
    sbom_path: Path | None = None,
) -> CheckContext:
    """Fetch all gate-relevant data for an ingested SBOM."""
    print(f"Fetching data for SBOM {sbom_id}...", file=sys.stderr)

    ctx = CheckContext(sbom_path=sbom_path, sbom_id=sbom_id)

    # SBOM detail.
    try:
        ctx.sbom_detail = client.find_sbom_by_id(sbom_id)
        ctx.sbom_name = ctx.sbom_detail.get("name", "")
    except Exception as e:
        print(f"warning: could not fetch SBOM detail: {e}", file=sys.stderr)

    # Packages and PURLs.
    try:
        packages = client.get_sbom_packages(sbom_id)
        purls = _extract_purls_from_packages(packages)
        ctx.purls = purls
    except Exception as e:
        print(f"warning: could not fetch SBOM packages: {e}", file=sys.stderr)

    # Vulnerability analysis.
    if ctx.purls:
        try:
            print(
                f"Analyzing {len(ctx.purls)} PURLs for vulnerabilities...",
                file=sys.stderr,
            )
            ctx.vuln_analysis = client.analyze_purls(ctx.purls)
        except Exception as e:
            print(f"warning: vulnerability analysis failed: {e}", file=sys.stderr)

    # Advisories.
    try:
        ctx.advisories = client.get_sbom_advisories(sbom_id)
    except Exception as e:
        print(f"warning: could not fetch advisories: {e}", file=sys.stderr)

    # Licenses.
    try:
        ctx.license_ids = client.get_sbom_license_ids(sbom_id)
    except Exception as e:
        print(f"warning: could not fetch license IDs: {e}", file=sys.stderr)

    return ctx


def _context_from_local(sbom_path: Path) -> CheckContext:
    """Extract PURLs from a local SBOM and analyze without uploading."""
    print(f"Extracting PURLs from {sbom_path}...", file=sys.stderr)

    ctx = CheckContext(sbom_path=sbom_path)
    ctx.purls = client.extract_purls_from_sbom(sbom_path)

    if not ctx.purls:
        print("warning: no PURLs found in SBOM", file=sys.stderr)
        return ctx

    print(
        f"Analyzing {len(ctx.purls)} PURLs for vulnerabilities...",
        file=sys.stderr,
    )

    try:
        ctx.vuln_analysis = client.analyze_purls(ctx.purls)
    except Exception as e:
        print(f"warning: vulnerability analysis failed: {e}", file=sys.stderr)

    return ctx


def _extract_purls_from_packages(packages: dict[str, Any]) -> list[str]:
    """Extract PURLs from the Trustify packages response."""
    purls: list[str] = []
    for item in packages.get("items", []):
        for purl in item.get("purl", []):
            purl_str = purl.get("purl", str(purl)) if isinstance(purl, dict) else str(purl)
            if purl_str.startswith("pkg:"):
                purls.append(purl_str)
    return purls


def main() -> None:
    args = _parse_args()

    if args.command == "list-checkers":
        _cmd_list_checkers()
    elif args.command == "check":
        _cmd_check(args)
    else:
        print("error: no command specified. Use 'check' or 'list-checkers'.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
