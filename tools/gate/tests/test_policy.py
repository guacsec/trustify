"""Tests for policy data models and config loading."""

import json

import pytest

from policy import GateResult, Violation, default_gate_config, load_gate_config


class TestViolation:
    def test_severity_rank_critical(self):
        v = Violation(kind="vulnerability", severity="critical", identifier="CVE-1", message="x")
        assert v.severity_rank == 4

    def test_severity_rank_high(self):
        v = Violation(kind="vulnerability", severity="high", identifier="CVE-1", message="x")
        assert v.severity_rank == 3

    def test_severity_rank_medium(self):
        v = Violation(kind="vulnerability", severity="medium", identifier="CVE-1", message="x")
        assert v.severity_rank == 2

    def test_severity_rank_low(self):
        v = Violation(kind="vulnerability", severity="low", identifier="CVE-1", message="x")
        assert v.severity_rank == 1

    def test_severity_rank_unknown(self):
        v = Violation(kind="vulnerability", severity="bogus", identifier="CVE-1", message="x")
        assert v.severity_rank == 0

    def test_severity_rank_case_insensitive(self):
        v = Violation(kind="vulnerability", severity="CRITICAL", identifier="CVE-1", message="x")
        assert v.severity_rank == 4


class TestGateResult:
    def test_passed_no_violations(self):
        r = GateResult(passed=True, violations=[], checkers_run=["builtin"])
        assert r.critical_count == 0
        assert r.high_count == 0
        assert r.medium_count == 0
        assert r.low_count == 0

    def test_counts(self):
        violations = [
            Violation(kind="v", severity="critical", identifier="a", message=""),
            Violation(kind="v", severity="critical", identifier="b", message=""),
            Violation(kind="v", severity="high", identifier="c", message=""),
            Violation(kind="v", severity="medium", identifier="d", message=""),
            Violation(kind="v", severity="low", identifier="e", message=""),
            Violation(kind="v", severity="low", identifier="f", message=""),
        ]
        r = GateResult(passed=False, violations=violations, checkers_run=["builtin"])
        assert r.critical_count == 2
        assert r.high_count == 1
        assert r.medium_count == 1
        assert r.low_count == 2


class TestLoadGateConfig:
    def test_load_valid(self, tmp_path):
        cfg = {"checkers": [{"name": "builtin", "config": {}}]}
        p = tmp_path / "gate.json"
        p.write_text(json.dumps(cfg))
        result = load_gate_config(p)
        assert result == cfg

    def test_load_missing_file(self, tmp_path):
        with pytest.raises(SystemExit):
            load_gate_config(tmp_path / "nonexistent.json")

    def test_load_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json {{{")
        with pytest.raises(SystemExit):
            load_gate_config(p)


class TestDefaultGateConfig:
    def test_has_builtin_checker(self):
        cfg = default_gate_config()
        assert len(cfg["checkers"]) == 1
        assert cfg["checkers"][0]["name"] == "builtin"
