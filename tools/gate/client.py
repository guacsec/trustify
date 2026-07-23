"""Synchronous HTTP client wrapping the Trustify v3 REST API for gate checks."""

import json
import sys
from pathlib import Path
from typing import Any

import httpx

from config import TRUSTIFY_TOKEN, TRUSTIFY_URL

TIMEOUT = 60.0


def _headers() -> dict[str, str]:
    h: dict[str, str] = {"Accept": "application/json"}
    if TRUSTIFY_TOKEN:
        h["Authorization"] = f"Bearer {TRUSTIFY_TOKEN}"
    return h


def _client() -> httpx.Client:
    return httpx.Client(base_url=TRUSTIFY_URL, headers=_headers(), timeout=TIMEOUT)


def _get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    with _client() as c:
        r = c.get(path, params=params)
        r.raise_for_status()
        return r.json()


def _post(path: str, json_body: Any) -> dict[str, Any]:
    with _client() as c:
        r = c.post(path, json=json_body)
        r.raise_for_status()
        return r.json()


# -- SBOM upload -------------------------------------------------------------

def upload_sbom(sbom_path: Path) -> dict[str, Any]:
    """Upload an SBOM document to Trustify. Returns the upload result."""
    content = sbom_path.read_bytes()

    content_type = "application/json"
    if sbom_path.suffix.lower() == ".xml":
        content_type = "application/xml"

    headers = _headers()
    headers["Content-Type"] = content_type

    with httpx.Client(base_url=TRUSTIFY_URL, headers=headers, timeout=TIMEOUT) as c:
        r = c.post("/api/v3/sbom", content=content)
        r.raise_for_status()
        return r.json()


# -- SBOM lookup -------------------------------------------------------------

def find_sbom_by_name(name: str) -> dict[str, Any] | None:
    """Find an SBOM by name. Returns the first match or None."""
    result = _get("/api/v3/sbom", {"q": f"name={name}", "limit": 1})
    items = result.get("items", [])
    if items:
        return items[0]
    return None


def find_sbom_by_id(sbom_id: str) -> dict[str, Any]:
    """Get an SBOM by its ID."""
    return _get(f"/api/v3/sbom/{sbom_id}")


def get_sbom_advisories(sbom_id: str) -> dict[str, Any]:
    """Get advisories affecting an SBOM."""
    return _get(f"/api/v3/sbom/{sbom_id}/advisory", {"limit": 1000})


def get_sbom_packages(sbom_id: str) -> dict[str, Any]:
    """Get packages within an SBOM."""
    return _get(f"/api/v3/sbom/{sbom_id}/packages", {"limit": 10000})


def get_sbom_license_ids(sbom_id: str) -> Any:
    """Get all license IDs for an SBOM."""
    return _get(f"/api/v3/sbom/{sbom_id}/all-license-ids")


# -- Vulnerability analysis --------------------------------------------------

def analyze_purls(purls: list[str]) -> dict[str, Any]:
    """Batch analyze PURLs for vulnerabilities."""
    return _post("/api/v3/vulnerability/analyze", {"purls": purls})


def get_vulnerability(vuln_id: str) -> dict[str, Any]:
    """Get vulnerability details."""
    return _get(f"/api/v3/vulnerability/{vuln_id}")


# -- SBOM PURL extraction (for files not yet ingested) -----------------------

def extract_purls_from_sbom(sbom_path: Path) -> list[str]:
    """Extract PURLs from a local SBOM file without uploading it.

    Parses CycloneDX and SPDX JSON formats locally. Falls back to the
    Trustify extract endpoint if local parsing cannot identify the format.
    """
    content = sbom_path.read_text()
    try:
        doc = json.loads(content)
    except json.JSONDecodeError:
        print(f"error: {sbom_path} is not valid JSON", file=sys.stderr)
        sys.exit(1)

    purls: list[str] = []

    # CycloneDX: look for components[].purl
    if "bomFormat" in doc or "components" in doc:
        for comp in doc.get("components", []):
            purl = comp.get("purl")
            if purl:
                purls.append(purl)
        # Also check metadata.component
        meta_comp = doc.get("metadata", {}).get("component", {})
        purl = meta_comp.get("purl")
        if purl:
            purls.append(purl)
        return purls

    # SPDX: look for packages[].externalRefs with purl type
    if "spdxVersion" in doc or "packages" in doc:
        for pkg in doc.get("packages", []):
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    if purl:
                        purls.append(purl)
        return purls

    # Fallback: try Trustify server-side extraction
    return _extract_purls_via_api(sbom_path)


def _extract_purls_via_api(sbom_path: Path) -> list[str]:
    """Use Trustify's extract-sbom-purls endpoint as a fallback."""
    content = sbom_path.read_bytes()
    headers = _headers()
    headers["Content-Type"] = "application/json"

    with httpx.Client(base_url=TRUSTIFY_URL, headers=headers, timeout=TIMEOUT) as c:
        r = c.post("/api/v3/ui/extract-sbom-purls", content=content)
        r.raise_for_status()
        result = r.json()

    purls = []
    for item in result if isinstance(result, list) else result.get("items", []):
        purl = item.get("purl") or item.get("name", "")
        if purl and purl.startswith("pkg:"):
            purls.append(purl)
    return purls
