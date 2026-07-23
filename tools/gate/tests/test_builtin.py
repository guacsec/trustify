"""Tests for the builtin checker plugin."""

from checkers import CheckContext
from checkers.builtin import BuiltinChecker


def _make_ctx(
    vuln_analysis=None,
    advisories=None,
    license_ids=None,
) -> CheckContext:
    return CheckContext(
        vuln_analysis=vuln_analysis,
        advisories=advisories,
        license_ids=license_ids,
    )


class TestVulnAnalysis:
    def test_no_vulns_passes(self):
        ctx = _make_ctx(vuln_analysis=[])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "low"}})
        assert result == []

    def test_critical_exceeds_high_threshold(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/foo@1.0",
            "vulnerabilities": [
                {"identifier": "CVE-2024-0001", "severity": "critical", "score": 9.8},
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "high"}})
        assert len(result) == 1
        assert result[0].identifier == "CVE-2024-0001"
        assert result[0].severity == "critical"
        assert result[0].checker == "builtin"

    def test_high_within_high_threshold_passes(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/foo@1.0",
            "vulnerabilities": [
                {"identifier": "CVE-2024-0002", "severity": "high", "score": 7.5},
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "high"}})
        assert result == []

    def test_score_exceeds_threshold(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/bar@2.0",
            "vulnerabilities": [
                {"identifier": "CVE-2024-0003", "severity": "medium", "score": 9.5},
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "high", "max_score": 9.0}})
        assert len(result) == 1
        assert result[0].score == 9.5

    def test_deny_list(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/baz@3.0",
            "vulnerabilities": [
                {"identifier": "CVE-2021-44228", "severity": "low", "score": 1.0},
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"deny": ["CVE-2021-44228"]}})
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_ignore_list(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/baz@3.0",
            "vulnerabilities": [
                {"identifier": "CVE-2024-9999", "severity": "critical", "score": 10.0},
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {
            "vulnerabilities": {"max_severity": "low", "ignore": ["CVE-2024-9999"]},
        })
        assert result == []

    def test_ignore_unfixed(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/baz@3.0",
            "vulnerabilities": [
                {
                    "identifier": "CVE-2024-0010",
                    "severity": "critical",
                    "score": 9.8,
                    "status": "not_affected",
                },
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {
            "vulnerabilities": {"max_severity": "low", "ignore_unfixed": True},
        })
        assert result == []

    def test_severity_inferred_from_score(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/x@1.0",
            "vulnerabilities": [
                {"identifier": "CVE-2024-0020", "score": 9.5},
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "high"}})
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_score_zero_not_confused_with_missing(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/x@1.0",
            "vulnerabilities": [
                {"identifier": "CVE-2024-0030", "score": 0, "severity": "low"},
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "high"}})
        assert result == []

    def test_scores_array(self):
        ctx = _make_ctx(vuln_analysis=[{
            "purl": "pkg:npm/x@1.0",
            "vulnerabilities": [
                {
                    "identifier": "CVE-2024-0040",
                    "severity": "medium",
                    "scores": [{"value": 9.2}, {"value": 7.1}],
                },
            ],
        }])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "high", "max_score": 9.0}})
        assert len(result) == 1
        assert result[0].score == 9.2

    def test_non_list_analysis_handled(self):
        ctx = _make_ctx(vuln_analysis={"unexpected": "format"})
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "low"}})
        assert result == []


class TestAdvisories:
    def test_advisory_critical_vuln(self):
        ctx = _make_ctx(advisories={
            "items": [{
                "identifier": "RHSA-2024:001",
                "vulnerabilities": [
                    {"identifier": "CVE-2024-0050", "severity": "critical", "score": 9.8},
                ],
            }],
        })
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "high"}})
        assert len(result) == 1
        assert "RHSA-2024:001" in result[0].message

    def test_advisory_deny_list(self):
        ctx = _make_ctx(advisories={
            "items": [{
                "identifier": "RHSA-2024:002",
                "vulnerabilities": [
                    {"identifier": "CVE-2021-44228", "severity": "low"},
                ],
            }],
        })
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"deny": ["CVE-2021-44228"]}})
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_empty_advisories_passes(self):
        ctx = _make_ctx(advisories={"items": []})
        checker = BuiltinChecker()
        result = checker.check(ctx, {"vulnerabilities": {"max_severity": "low"}})
        assert result == []


class TestLicenses:
    def test_deny_glob(self):
        ctx = _make_ctx(license_ids=["MIT", "GPL-3.0-only", "Apache-2.0"])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"licenses": {"deny": ["GPL-*"]}})
        assert len(result) == 1
        assert result[0].identifier == "GPL-3.0-only"

    def test_allow_list(self):
        ctx = _make_ctx(license_ids=["MIT", "WTFPL", "Apache-2.0"])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"licenses": {"allow": ["MIT", "Apache-2.0"]}})
        assert len(result) == 1
        assert result[0].identifier == "WTFPL"

    def test_deny_and_allow_no_double_violation(self):
        ctx = _make_ctx(license_ids=["GPL-3.0-only"])
        checker = BuiltinChecker()
        result = checker.check(ctx, {
            "licenses": {"deny": ["GPL-*"], "allow": ["MIT"]},
        })
        # Should get exactly one violation (deny), not two (deny + not-in-allow).
        assert len(result) == 1
        assert result[0].severity == "high"

    def test_no_license_config_passes(self):
        ctx = _make_ctx(license_ids=["GPL-3.0-only"])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"licenses": {}})
        assert result == []

    def test_dict_format_licenses(self):
        ctx = _make_ctx(license_ids={"items": ["MIT", "GPL-3.0-only"]})
        checker = BuiltinChecker()
        result = checker.check(ctx, {"licenses": {"deny": ["GPL-*"]}})
        assert len(result) == 1

    def test_empty_licenses_passes(self):
        ctx = _make_ctx(license_ids=[])
        checker = BuiltinChecker()
        result = checker.check(ctx, {"licenses": {"deny": ["GPL-*"]}})
        assert result == []


class TestCombined:
    def test_vuln_and_license_violations_combined(self):
        ctx = _make_ctx(
            vuln_analysis=[{
                "purl": "pkg:npm/foo@1.0",
                "vulnerabilities": [
                    {"identifier": "CVE-2024-0001", "severity": "critical", "score": 9.8},
                ],
            }],
            license_ids=["GPL-3.0-only"],
        )
        checker = BuiltinChecker()
        result = checker.check(ctx, {
            "vulnerabilities": {"max_severity": "high"},
            "licenses": {"deny": ["GPL-*"]},
        })
        assert len(result) == 2
        kinds = {v.kind for v in result}
        assert kinds == {"vulnerability", "license"}

    def test_all_none_context_passes(self):
        ctx = _make_ctx()
        checker = BuiltinChecker()
        result = checker.check(ctx, {})
        assert result == []
