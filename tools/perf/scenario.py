"""Load scenario data from a JSON5 file.

Scenario files provide pre-computed IDs (SBOMs, advisories, PURLs, etc.)
that parameterized tests use to hit detail endpoints. Fields set to null
disable the corresponding tests. List-valued fields (get_analysis_component,
get_recommendations, delete_sbom_pool) accept a single string or an array.

Set TOOLS_PERF_SCENARIO_FILE to a path to enable. See etc/ for examples.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

try:
    import json5 as _json5

    def _load(path: str) -> dict[str, Any]:
        with open(path, encoding="utf-8") as fh:
            return _json5.load(fh)  # type: ignore[no-any-return]

except ImportError:
    _json5 = None  # type: ignore[assignment]

    def _load(path: str) -> dict[str, Any]:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)  # type: ignore[no-any-return]


@dataclass(frozen=True)
class Scenario:
    """Pre-computed test data loaded from a scenario file."""

    get_sbom: str | None = None
    get_sbom_advisories: str | None = None
    get_sbom_packages: str | None = None
    get_sbom_related: str | None = None
    get_vulnerability: str | None = None
    sbom_by_package: str | None = None
    sbom_license_ids: str | None = None
    analyze_purl: str | None = None
    get_purl_details: str | None = None
    get_recommendations: list[str] = field(default_factory=list)
    download_advisory: str | None = None
    get_advisory: str | None = None
    download_sbom: str | None = None
    get_sbom_license_export: str | None = None
    count_sbom_by_package: str | None = None
    get_sbom_group: str | None = None
    get_product: str | None = None
    get_organization: str | None = None
    get_base_purl: str | None = None
    get_analysis_component: list[str] = field(default_factory=list)
    render_sbom_graph: str | None = None
    get_importer: str | None = None
    get_weakness: str | None = None
    get_spdx_license: str | None = None
    delete_sbom_pool: list[str] = field(default_factory=list)


def load_scenario() -> Scenario:
    """Load scenario from TOOLS_PERF_SCENARIO_FILE env var, or return empty."""
    path = os.environ.get("TOOLS_PERF_SCENARIO_FILE", "")
    if not path:
        log.warning(
            "TOOLS_PERF_SCENARIO_FILE not set; "
            "scenario-dependent tests will be skipped"
        )
        return Scenario()

    log.info("Loading scenario from %s", path)
    raw = _load(path)

    def _to_list(val: Any) -> list[str]:
        """Coerce a scalar, list, or None into a list of strings."""
        if isinstance(val, list):
            return [str(v) for v in val if v is not None]
        if val is not None:
            return [str(val)]
        return []

    recs_list = _to_list(raw.get("get_recommendations"))
    pool_list = _to_list(raw.get("delete_sbom_pool"))
    analysis_list = _to_list(raw.get("get_analysis_component"))

    list_fields = (
        "get_recommendations",
        "delete_sbom_pool",
        "get_analysis_component",
    )

    kwargs: dict[str, Any] = {}
    for fld in dataclasses.fields(Scenario):
        if fld.name in list_fields:
            continue
        val = raw.get(fld.name)
        if val is not None:
            kwargs[fld.name] = str(val)

    return Scenario(
        get_recommendations=recs_list,
        delete_sbom_pool=pool_list,
        get_analysis_component=analysis_list,
        **kwargs,
    )


# Singleton loaded once at import time.
SCENARIO = load_scenario()
