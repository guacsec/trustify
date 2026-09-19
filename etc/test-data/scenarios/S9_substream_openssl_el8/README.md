# S9 — Within-major sub-stream: compare on the box's own z-stream line (openssl)

Isolates **z-stream/build-line matching within a major**. RHEL 8 minors carry different openssl lines
(8.2 = `1.1.1c`, 8.10 GA = `1.1.1k`), each fixed on its own line. An `el8_2` box must be compared to the
8.2 fix, never the GA/other-minor fix (standard §3, z-stream lines).

## Data — CVE-2023-0286 `openssl` fixes
| stream | fix |
|---|---|
| RHEL 8.2 (`rhel_aus/e4s/tus:8.2`) | `1:1.1.1c-21.el8_2` |
| RHEL 8.10 GA (`enterprise_linux:8`) | `1:1.1.1k-9.el8_7` |

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `openssl`, `el8_2` line) | CVE-2023-0286 |
|---|---|
| `sbom_openssl_el8.2_below-fix` (`1:1.1.1c-15.el8_2`) | affected |
| `sbom_openssl_el8.2_patched` (`1:1.1.1c-21.el8_2`) | not_affected |

Both boxes are on the `el8_2` line → compared to the 8.2 fix `1.1.1c-21.el8_2`: `-15` below → affected,
`-21` at → not_affected. (Comparing the `el8_2` build to the GA `1.1.1k` line would be a different-line
comparison and is not valid.)

## Files
- SBOMs: `sbom_openssl_el8.2_below-fix.{cdx,spdx}.json`, `sbom_openssl_el8.2_patched.{cdx,spdx}.json`.
- Advisory: `vex/CVE-2023-0286.json` (Red Hat CSAF); `cve/` MITRE record.
