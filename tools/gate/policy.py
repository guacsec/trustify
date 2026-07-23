"""Policy data models and loading for the Trustify gate.

This module defines the data structures only. Evaluation logic lives in
the ``checkers`` package, which implements a plugin architecture.
"""

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Severity ranking (higher = more severe).
SEVERITY_RANK = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class Violation:
    """A single policy violation produced by any checker."""

    kind: str  # "vulnerability", "license", "conforma", or custom
    severity: str  # "critical", "high", "medium", "low", "none"
    identifier: str  # CVE ID, license ID, rule name, etc.
    message: str
    checker: str = ""  # which checker produced this
    score: float = 0.0
    purl: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity.lower(), 0)


@dataclass
class GateResult:
    """Aggregated result from all checkers."""

    passed: bool
    violations: list[Violation] = field(default_factory=list)
    warnings: list[Violation] = field(default_factory=list)
    checkers_run: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity.lower() == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity.lower() == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.violations if v.severity.lower() == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.violations if v.severity.lower() == "low")


def load_gate_config(path: Path) -> dict[str, Any]:
    """Load the gate configuration file (JSON).

    The config file specifies which checkers to run and their individual
    configuration. Structure::

        {
          "checkers": [
            {
              "name": "builtin",
              "config": { ... builtin-specific config ... }
            },
            {
              "name": "conforma",
              "config": { ... conforma-specific config ... }
            }
          ]
        }
    """
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"error: invalid gate config JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"error: gate config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return raw


def default_gate_config() -> dict[str, Any]:
    """Return a default config that runs only the builtin checker."""
    return {
        "checkers": [
            {
                "name": "builtin",
                "config": {
                    "vulnerabilities": {
                        "max_severity": "high",
                        "max_score": 9.0,
                    },
                },
            },
        ],
    }
