"""Built-in checker: severity thresholds, CVSS scores, and license policy.

This checker evaluates Trustify vulnerability analysis and advisory data
against simple declarative rules (max severity, max score, deny/allow
lists). No external tools required.

Config example (inside gate config ``checkers`` entry)::

    {
      "name": "builtin",
      "config": {
        "vulnerabilities": {
          "max_severity": "high",
          "max_score": 9.0,
          "deny": ["CVE-2024-0001"],
          "ignore": ["CVE-2024-9999"],
          "ignore_unfixed": false
        },
        "licenses": {
          "deny": ["GPL-3.0*", "AGPL-*"],
          "allow": ["MIT", "Apache-2.0", "BSD-*"]
        }
      }
    }
"""

import re
from dataclasses import dataclass
from typing import Any

from checkers import CheckContext, register_checker
from policy import SEVERITY_RANK, Violation

CHECKER_NAME = "builtin"


class BuiltinChecker:
    """Evaluates vulnerabilities and licenses against declarative thresholds."""

    @property
    def name(self) -> str:
        return CHECKER_NAME

    def check(self, ctx: CheckContext, config: dict[str, Any]) -> list[Violation]:
        violations: list[Violation] = []

        vuln_config = config.get("vulnerabilities", {})
        lic_config = config.get("licenses", {})

        if ctx.vuln_analysis is not None:
            violations.extend(_check_vuln_analysis(ctx.vuln_analysis, vuln_config))

        if ctx.advisories is not None:
            violations.extend(_check_advisories(ctx.advisories, vuln_config))

        if ctx.license_ids is not None:
            violations.extend(_check_licenses(ctx.license_ids, lic_config))

        for v in violations:
            v.checker = CHECKER_NAME

        return violations


# -- Shared config parsing ---------------------------------------------------

@dataclass
class _VulnRules:
    max_sev: str
    max_sev_rank: int
    max_score: float
    deny_cves: list[str]
    ignore_cves: set[str]
    ignore_unfixed: bool


def _parse_vuln_rules(config: dict[str, Any]) -> _VulnRules:
    max_sev = config.get("max_severity", "critical").lower()
    return _VulnRules(
        max_sev=max_sev,
        max_sev_rank=SEVERITY_RANK.get(max_sev, 4),
        max_score=float(config.get("max_score", 10.0)),
        deny_cves=config.get("deny", []),
        ignore_cves=set(config.get("ignore", [])),
        ignore_unfixed=config.get("ignore_unfixed", False),
    )


# -- Vulnerability analysis --------------------------------------------------

def _check_vuln_analysis(
    analysis: Any,
    config: dict[str, Any],
) -> list[Violation]:
    rules = _parse_vuln_rules(config)

    violations: list[Violation] = []

    items = analysis if isinstance(analysis, list) else []
    for item in items:
        purl = item.get("purl", "")
        for vuln in item.get("vulnerabilities", []):
            vuln_id = vuln.get("identifier", vuln.get("id", "unknown"))

            if vuln_id in rules.ignore_cves:
                continue

            if vuln_id in rules.deny_cves:
                violations.append(Violation(
                    kind="vulnerability",
                    severity="critical",
                    identifier=vuln_id,
                    message=f"Denied CVE {vuln_id} found in {purl}",
                    purl=purl,
                ))
                continue

            severity = _extract_severity(vuln)
            score = _extract_score(vuln)

            status = vuln.get("status", "").lower()
            if rules.ignore_unfixed and status in ("not_affected", "under_investigation"):
                continue

            sev_rank = SEVERITY_RANK.get(severity, 0)
            if sev_rank > rules.max_sev_rank:
                violations.append(Violation(
                    kind="vulnerability",
                    severity=severity,
                    identifier=vuln_id,
                    message=(
                        f"{severity.upper()} vulnerability {vuln_id} "
                        f"(score: {score}) in {purl}"
                    ),
                    score=score,
                    purl=purl,
                ))
            elif score > rules.max_score:
                violations.append(Violation(
                    kind="vulnerability",
                    severity=severity,
                    identifier=vuln_id,
                    message=(
                        f"Vulnerability {vuln_id} score {score} exceeds "
                        f"threshold {rules.max_score} in {purl}"
                    ),
                    score=score,
                    purl=purl,
                ))

    return violations


# -- Advisory checks ---------------------------------------------------------

def _check_advisories(
    advisories: dict[str, Any],
    config: dict[str, Any],
) -> list[Violation]:
    rules = _parse_vuln_rules(config)
    violations: list[Violation] = []

    for item in advisories.get("items", []):
        advisory_id = item.get("identifier", item.get("uuid", "unknown"))

        for vuln in item.get("vulnerabilities", []):
            vuln_id = vuln.get("identifier", vuln.get("id", "unknown"))

            if vuln_id in rules.ignore_cves:
                continue

            if vuln_id in rules.deny_cves:
                violations.append(Violation(
                    kind="vulnerability",
                    severity="critical",
                    identifier=vuln_id,
                    message=f"Denied CVE {vuln_id} in advisory {advisory_id}",
                ))
                continue

            severity = _extract_severity(vuln)
            score = _extract_score(vuln)
            sev_rank = SEVERITY_RANK.get(severity, 0)

            if sev_rank > rules.max_sev_rank:
                violations.append(Violation(
                    kind="vulnerability",
                    severity=severity,
                    identifier=vuln_id,
                    message=(
                        f"{severity.upper()} {vuln_id} "
                        f"(score: {score}) via advisory {advisory_id}"
                    ),
                    score=score,
                ))
            elif score > rules.max_score:
                violations.append(Violation(
                    kind="vulnerability",
                    severity=severity,
                    identifier=vuln_id,
                    message=(
                        f"{vuln_id} score {score} exceeds "
                        f"threshold {rules.max_score} via advisory {advisory_id}"
                    ),
                    score=score,
                ))

    return violations


# -- License checks ----------------------------------------------------------

def _check_licenses(
    license_ids: Any,
    config: dict[str, Any],
) -> list[Violation]:
    deny: list[str] = config.get("deny", [])
    allow: list[str] = config.get("allow", [])

    if not deny and not allow:
        return []

    violations: list[Violation] = []

    ids: list[str] = []
    if isinstance(license_ids, list):
        ids = license_ids
    elif isinstance(license_ids, dict):
        ids = license_ids.get("items", license_ids.get("licenses", []))

    for lic in ids:
        lic_str = str(lic)
        denied = False

        for pattern in deny:
            if _glob_match(pattern, lic_str):
                violations.append(Violation(
                    kind="license",
                    severity="high",
                    identifier=lic_str,
                    message=f"Denied license '{lic_str}' (matches '{pattern}')",
                ))
                denied = True
                break

        if not denied and allow and not any(_glob_match(p, lic_str) for p in allow):
            violations.append(Violation(
                kind="license",
                severity="medium",
                identifier=lic_str,
                message=f"License '{lic_str}' not in allow list",
            ))

    return violations


# -- Helpers -----------------------------------------------------------------

def _extract_severity(vuln: dict[str, Any]) -> str:
    severity = vuln.get("severity", "")
    if severity:
        return severity.lower()

    score = _extract_score(vuln)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _extract_score(vuln: dict[str, Any]) -> float:
    for key in ("score", "base_score"):
        val = vuln.get(key)
        if val is not None:
            return float(val)

    cvss_score = vuln.get("cvss", {}).get("score")
    if cvss_score is not None:
        return float(cvss_score)

    scores = vuln.get("scores", vuln.get("cvss3_scores", []))
    if scores:
        max_score = 0.0
        for s in scores:
            if isinstance(s, dict):
                for k in ("value", "score", "base_score"):
                    v = s.get(k)
                    if v is not None:
                        max_score = max(max_score, float(v))
                        break
            elif isinstance(s, (int, float)):
                max_score = max(max_score, float(s))
        return max_score

    return 0.0


def _glob_match(pattern: str, value: str) -> bool:
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return bool(re.fullmatch(regex, value, re.IGNORECASE))


register_checker(CHECKER_NAME, BuiltinChecker)
