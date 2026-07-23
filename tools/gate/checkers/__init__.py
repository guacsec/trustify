"""Checker plugin system for the Trustify gate.

Each checker is a module in this package that registers itself via
``register_checker()``. The gate loads checkers by name from the gate
config file and calls ``check()`` on each one.

To add a new checker:

1. Create ``checkers/mychecker.py``
2. Implement a class with the ``Checker`` protocol
3. Call ``register_checker("mychecker", MyChecker)`` at module level
4. Import the module in this ``__init__.py``

The checker receives a ``CheckContext`` with all the data it needs
(SBOM info, vulnerabilities, advisories, licenses, raw SBOM path)
and its own config dict from the gate config file.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from policy import Violation


@dataclass
class CheckContext:
    """Data available to all checkers.

    Populated by the gate before invoking checkers. Fields may be None
    if the corresponding data was not fetched (e.g. no SBOM uploaded).
    """

    sbom_path: Path | None = None
    sbom_id: str = ""
    sbom_name: str = ""
    purls: list[str] = field(default_factory=list)
    vuln_analysis: Any = None  # response from POST /vulnerability/analyze
    advisories: dict[str, Any] | None = None  # response from GET /sbom/{id}/advisory
    license_ids: Any = None  # response from GET /sbom/{id}/all-license-ids
    sbom_detail: dict[str, Any] | None = None  # response from GET /sbom/{id}


class Checker(Protocol):
    """Protocol that all checker plugins must implement."""

    @property
    def name(self) -> str:
        """Short identifier for this checker (e.g. 'builtin', 'conforma')."""
        ...

    def check(self, ctx: CheckContext, config: dict[str, Any]) -> list[Violation]:
        """Run the check and return a list of violations.

        An empty list means the check passed. The checker should not
        raise exceptions for policy failures -- only for infrastructure
        errors (unreachable services, bad config, etc.).
        """
        ...


# -- Registry ----------------------------------------------------------------

_registry: dict[str, type[Checker]] = {}


def register_checker(name: str, cls: type[Checker]) -> None:
    """Register a checker class by name."""
    _registry[name] = cls


def get_checker(name: str) -> type[Checker]:
    """Look up a registered checker by name. Raises KeyError if unknown."""
    if name not in _registry:
        available = ", ".join(sorted(_registry)) or "(none)"
        raise KeyError(
            f"Unknown checker '{name}'. Available checkers: {available}"
        )
    return _registry[name]


def available_checkers() -> list[str]:
    """Return names of all registered checkers."""
    return sorted(_registry)


# Import checker modules so they self-register on import.
from checkers import builtin as _builtin  # noqa: E402, F401
from checkers import conforma as _conforma  # noqa: E402, F401
