# S23 — SUSE PURL matching by codestream (official BCI SBOMs × SUSE CSAF VEX)

Real-world PURL matching with only official SUSE documents. Both sides carry `pkg:rpm/suse/…`
PURLs. Matching them correctly requires four SUSE specifics, each a distinct failure mode:

1. **Fixes are `recommended`, not `fixed`.** SUSE VEX states the package version to update to as
   `product_status.recommended`, per product. It implies "affected before X" and "fixed from X on" (rules
   `purl_suse_recommended_before` and `purl_suse_recommended`).
2. **"Any version" is a versionless PURL.** `known_not_affected` (and some `known_affected`) for a
   whole product use e.g. `pkg:rpm/suse/libopenssl3@?upstream=openssl-3.src.rpm`, stored as the
   exact, empty version (rule `purl_suse_any_version`).
3. **The codestream is a release prefix, not a dist tag.** `3.1.4-150600.5.39.1` is SLE 15 SP6
   (`150600`), `150700.` SP7, `160000.` SLE 16.0, `slfo.1.1_7.1` SUSE Linux Micro 6.1. Tumbleweed
   and Micro 6.0 releases (`13.1`, `6.1`) carry none.
4. **One document lists the fixes of all codestreams side by side.** Compared across codestreams, the
   SP6 build `3.1.4-150600.5.7.1` is "newer" than Tumbleweed's fix `3.1.4-13.1` (`150600 > 13`), and
   `fixed` beats `affected` in the verdict. Codestream scoping is therefore strict. Only equal
   codestreams match, and a codestream on only one side is a mismatch.

## Data

### SBOMs — `registry.suse.com/bci/bci-base`, amd64

SUSE's own `obs_build_generate_sbom` output. SUSE ships it as cosign attestations (SPDX and
CycloneDX predicates) on the **per-architecture** image digest. The tag's index digest has none.

| tag | amd64 digest | built | `libopenssl3`, `openssl-3`, `libopenssl-3-fips-provider` | `openssl` |
|---|---|---|---|---|
| `15.6.47.11.1` | `sha256:94e60a27995231a4c54445850330686074ccd8d583d4135d384f6e9243f6fe95` | 2024-07-29 | `3.1.4-150600.5.7.1` | `3.1.4-150600.2.1` |
| `15.6.47.26.19` | `sha256:3d195d20c50b2c9d3676eeb18c9cd2a1f2407fab9978aad54dd2661ce6944615` | 2025-12-16 | `3.1.4-150600.5.39.1` | `3.1.4-150600.2.1` |

Retrieval:

```sh
skopeo inspect --raw docker://registry.suse.com/bci/bci-base:15.6.47.11.1   # pick the amd64 manifest
cosign download attestation registry.suse.com/bci/bci-base@sha256:94e60a27… \
  | jq -r .payload | base64 -d | jq 'select(.predicateType == "https://cyclonedx.org/bom") | .predicate'
```

The predicates are stored as extracted, re-indented only. The SPDX ones are xz-compressed (file lists).

### Advisories — `https://ftp.suse.com/pub/projects/security/csaf-vex/`

Unmodified, xz-compressed. Rows for the SBOM's packages (base PURL `pkg:rpm/suse/<name>`):

| CVE | SLE 15 SP6 | other codestreams in the same document |
|---|---|---|
| CVE-2024-6119 | `recommended` `3.1.4-150600.5.15.1` | SP4 `3.0.8-150400.4.63.1`, SP5 `3.0.8-150500.5.42.1`, SP7 `3.2.3-150700.3.20`, 16.0 `3.5.0-160000.3.2`, 16.1, Micro 6.0 `3.1.4-6.1`, Micro 6.1 `3.1.4-slfo.1.1_3.10`, Tumbleweed `3.1.4-13.1` |
| CVE-2025-9230 | `recommended` `3.1.4-150600.5.39.1` | SP4, SP5, SP7, 16.0, 16.1, Micro, Tumbleweed; versionless `openssl-3@` `known_affected` for *Module for Certifications 15 SP7* |
| CVE-2024-9143 | `known_not_affected`, versionless | `recommended` SP7 `3.2.3-150700.3.20`, 16.0, 16.1, Tumbleweed `3.1.4-15.1` |

The meta package `openssl` only has versionless statements: `known_not_affected` in all three
documents, plus `known_affected` for SLE 12 SP2 products in CVE-2025-9230. There are also
`recommended` rows for SUSE Liberty Linux (`…el9_4`, which carry no SUSE codestream).

CVE-2024-6119 and CVE-2025-9230 list SLES 15 SP1 container-host products with CPEs like
`cpe:/o:suse:sles:15:sp1:chost-amazon:suse-sles-15-sp1-chost-byos-v20210304-hvm-ssd-x86_64`. The 7th
component isn't a language tag. Trustify drops it (ANY) rather than rejecting the document.

## Expected (SBOM × CVE) — matches `expected.json`

The same verdicts for `libopenssl3`, `openssl-3` and `libopenssl-3-fips-provider`, and for the
CycloneDX and SPDX variant of each SBOM.

| SBOM | package | CVE-2024-6119 | CVE-2025-9230 | CVE-2024-9143 |
|---|---|---|---|---|
| `15.6.47.11.1` | `openssl-3` family `…150600.5.7.1` | **affected** — before the SP6 fix `5.15.1` | **affected** — before the SP6 fix `5.39.1` | **not_affected** — versionless |
| `15.6.47.26.19` | `openssl-3` family `…150600.5.39.1` | **fixed** — from `5.15.1` on | **fixed** — exactly the SP6 fix | **not_affected** — versionless |
| both | `openssl` `3.1.4-150600.2.1` | not_affected | not_affected | not_affected |

### Why

- **Negative controls (codestream scoping).** Without it, the old build would also match
  Tumbleweed `3.1.4-13.1`, Micro 6.0 `3.1.4-6.1` and `slfo.1.1_3.10` as "≥ fix" → `fixed`, and the
  verdict would flip from affected to **fixed**. Both builds would also be "before" SP7 `3.2.3-…`
  and 16.0 `3.5.0-…` → `affected`, which shows up as evidence. The evidence test
  `suse_recommended_codestream` asserts that only the SP6 range matches.
- **CVE-2024-9143.** SP6 is `known_not_affected` (versionless). The SP7/16.0/Tumbleweed fixes are
  other codestreams, so no "before the fix → affected" applies.
- **`openssl` × CVE-2025-9230.** The versionless statements conflict: `known_affected` for SLE 12 SP2,
  `known_not_affected` for the rest (including SP6). The product isn't part of the match yet, so
  both are evidence (`purl_suse_any_version`, confidence 0.7), and `not_affected` wins over
  `affected`. This needs one evidence record per status: before, one of them was silently dropped.
  The same applies to `openssl-3` × CVE-2025-9230 (*Module for Certifications 15 SP7*), where
  `fixed` / `affected` decide anyway.

## Files

- SBOMs: `sbom/bci-base_15.6.47.11.1.{cdx.json,spdx.json.xz}`, `sbom/bci-base_15.6.47.26.19.{cdx.json,spdx.json.xz}`
- Advisories: `vex/cve-2024-6119.json.xz`, `vex/cve-2025-9230.json.xz`, `vex/cve-2024-9143.json.xz`
