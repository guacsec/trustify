# S3 — Wrong-product / CPE-context not checked (TC-5171), hummingbird

**Component:** `pkg:rpm/redhat/curl@7.61.1-34.el8_10.11` (RHEL 8 OS)
**SBOM:** `sbom_curl_el8.cdx.json`

## The bug (same root cause as S4: CPE context not checked)
`hummingbird` (`cpe:/a:redhat:hummingbird:1`) is a real, *separate* Red Hat product that bundles
curl. The engine attaches hummingbird advisories to the RHEL-8 OS curl by name, ignoring that the
context CPE product is `hummingbird`, not `enterprise_linux`.

## Two flavors here (hummingbird bundles the same libs as el8, so overlap is high)
| CVE | el8-OS curl (VEX) | hummingbird | Verdict | Flavor |
|---|---|---|---|---|
| CVE-2025-10966 | known_not_affected | fixed | **not_affected** | **CLEAN** — whole CVE false (only hummingbird matches) |
| CVE-2025-10148 | affected + not_affected (mixed) | fixed | affected via el8, but **hummingbird context is spurious** | duplicate-row |
| CVE-2025-13034 | known_affected | fixed | affected via el8, but **hummingbird context is spurious** | duplicate-row |

- **CLEAN:** el8 curl is `not_affected`; the CVE only appears because of the hummingbird row → should not appear at all.
- **duplicate-row:** el8 curl is genuinely affected, so the CVE belongs — but reporting it under a
  `hummingbird:1` context is a wrong-product mis-attribution (should be `enterprise_linux:8`).

> Note: for a *whole-CVE-false* TC-5171 reproducer, **S4 (satellite / python3-chardet) is stronger** —
> Satellite ships packages el8-OS doesn't track, so el8 is entirely absent. hummingbird overlaps el8's
> core libraries, so most of its matches are duplicate rows rather than fully-false CVEs.

## Files
- `sbom_curl_el8.cdx.json` — upload.
- `vex/` — the 3 canonical CSAF/VEX docs. `vex_extra/` — more curl/openssl/gnutls/python hummingbird CVEs.
- `cve/` — CVE Project records.

## Reproduce
1. Ingest `vex/*.json`; 2. upload the SBOM; 3. `GET /sbom/{id}/advisory`.
   BUG: curl shown `affected` under `cpe:/a:redhat:hummingbird:1`. Correct: CVE-2025-10966 absent; the
   other two shown only under `enterprise_linux:8`, never hummingbird.
