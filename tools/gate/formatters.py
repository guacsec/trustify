"""Output formatters for the Trustify gate."""

import json
import sys
from typing import Any, TextIO

from policy import GateResult, Violation

# ANSI color codes for terminal output.
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_SEV_COLORS = {
    "critical": _RED,
    "high": _RED,
    "medium": _YELLOW,
    "low": _CYAN,
}


def format_result(result: GateResult, fmt: str, out: TextIO = sys.stdout) -> None:
    """Format and write a GateResult to the given stream."""
    match fmt:
        case "json":
            _format_json(result, out)
        case "table":
            _format_table(result, out)
        case "sarif":
            _format_sarif(result, out)
        case "junit":
            _format_junit(result, out)
        case _:
            print(f"error: unknown format '{fmt}'", file=sys.stderr)
            sys.exit(1)


# -- JSON --------------------------------------------------------------------

def _format_json(result: GateResult, out: TextIO) -> None:
    doc = {
        "passed": result.passed,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "total": len(result.violations),
        },
        "checkers": result.checkers_run,
        "violations": [_violation_dict(v) for v in result.violations],
    }
    json.dump(doc, out, indent=2)
    out.write("\n")


def _violation_dict(v: Violation) -> dict[str, Any]:
    d: dict[str, Any] = {
        "kind": v.kind,
        "severity": v.severity,
        "identifier": v.identifier,
        "message": v.message,
        "checker": v.checker,
    }
    if v.score > 0:
        d["score"] = v.score
    if v.purl:
        d["purl"] = v.purl
    return d


# -- Table -------------------------------------------------------------------

def _format_table(result: GateResult, out: TextIO) -> None:
    is_tty = hasattr(out, "isatty") and out.isatty()

    def _c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if is_tty else text

    status = _c(_GREEN, "PASS") if result.passed else _c(_RED, "FAIL")
    out.write(f"\n{_c(_BOLD, 'Trustify Gate')}: {status}\n")
    out.write(f"Checkers: {', '.join(result.checkers_run)}\n\n")

    if not result.violations:
        out.write("No policy violations found.\n\n")
        return

    out.write(
        f"  {_c(_RED, 'Critical')}: {result.critical_count}  "
        f"{_c(_RED, 'High')}: {result.high_count}  "
        f"{_c(_YELLOW, 'Medium')}: {result.medium_count}  "
        f"{_c(_CYAN, 'Low')}: {result.low_count}  "
        f"Total: {len(result.violations)}\n\n"
    )

    # Column widths.
    sev_w = 10
    id_w = max((len(v.identifier) for v in result.violations), default=12)
    id_w = max(id_w, 12)
    chk_w = max((len(v.checker) for v in result.violations), default=8)
    chk_w = max(chk_w, 8)

    header = f"  {'SEVERITY':<{sev_w}} {'IDENTIFIER':<{id_w}} {'CHECKER':<{chk_w}} MESSAGE"
    out.write(f"{_c(_BOLD, header)}\n")
    out.write(f"  {'-' * (sev_w + id_w + chk_w + 20)}\n")

    sorted_violations = sorted(result.violations, key=lambda v: -v.severity_rank)
    for v in sorted_violations:
        color = _SEV_COLORS.get(v.severity.lower(), "")
        sev = _c(color, v.severity.upper().ljust(sev_w))
        out.write(f"  {sev} {v.identifier:<{id_w}} {v.checker:<{chk_w}} {v.message}\n")

    out.write("\n")


# -- SARIF -------------------------------------------------------------------

def _format_sarif(result: GateResult, out: TextIO) -> None:
    """SARIF v2.1.0 output for GitHub Code Scanning and IDE integration."""
    rules = []
    results_list = []
    rule_index: dict[str, int] = {}

    for v in result.violations:
        if v.identifier not in rule_index:
            rule_index[v.identifier] = len(rules)
            rules.append({
                "id": v.identifier,
                "shortDescription": {"text": v.identifier},
                "defaultConfiguration": {
                    "level": _sarif_level(v.severity),
                },
            })

        results_list.append({
            "ruleId": v.identifier,
            "ruleIndex": rule_index[v.identifier],
            "level": _sarif_level(v.severity),
            "message": {"text": v.message},
            "properties": {
                "checker": v.checker,
                "kind": v.kind,
                **({"purl": v.purl} if v.purl else {}),
                **({"score": v.score} if v.score > 0 else {}),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "trustify-gate",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/guacsec/trustify",
                        "rules": rules,
                    },
                },
                "results": results_list,
            },
        ],
    }
    json.dump(sarif, out, indent=2)
    out.write("\n")


def _sarif_level(severity: str) -> str:
    match severity.lower():
        case "critical" | "high":
            return "error"
        case "medium":
            return "warning"
        case _:
            return "note"


# -- JUnit -------------------------------------------------------------------

def _format_junit(result: GateResult, out: TextIO) -> None:
    """JUnit XML output for CI/CD systems."""
    total = len(result.violations)
    failures = sum(1 for v in result.violations if v.severity_rank >= 3)
    errors = 0

    out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    out.write(
        f'<testsuites tests="{total + 1}" failures="{failures}" errors="{errors}">\n'
    )
    out.write(
        f'  <testsuite name="trustify-gate" tests="{total + 1}" '
        f'failures="{failures}" errors="{errors}">\n'
    )

    # Overall gate result as a test case.
    if result.passed:
        out.write('    <testcase name="gate-policy-check" classname="trustify.gate"/>\n')
    else:
        out.write('    <testcase name="gate-policy-check" classname="trustify.gate">\n')
        out.write(
            f'      <failure message="Policy check failed with {total} violation(s)">'
            f"Critical: {result.critical_count}, High: {result.high_count}, "
            f"Medium: {result.medium_count}, Low: {result.low_count}"
            f"</failure>\n"
        )
        out.write("    </testcase>\n")

    # Each violation as a test case.
    for v in result.violations:
        classname = f"trustify.gate.{v.checker}"
        out.write(f'    <testcase name="{_xml_escape(v.identifier)}" classname="{classname}">\n')
        if v.severity_rank >= 3:
            out.write(
                f'      <failure message="{_xml_escape(v.message)}" '
                f'type="{v.severity.upper()}">{_xml_escape(v.message)}</failure>\n'
            )
        else:
            out.write(
                f"      <system-out>{_xml_escape(v.message)}</system-out>\n"
            )
        out.write("    </testcase>\n")

    out.write("  </testsuite>\n")
    out.write("</testsuites>\n")


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
