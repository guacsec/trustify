# S18 — File digests (Beckhoff TwinCAT HMI Server)

Correlation by the hash of a delivered file. The advisory gives the SHA-256 of each fixed package
file, and the SBOM states the hashes of its components. A component with the same digest is the
product the advisory names, whatever its name or PURL.

## Data (Beckhoff, VDE-2025-106: CVE-2025-41768)

The advisory is published, unmodified. Each package comes in four variants:

| product | identification | status |
|---|---|---|
| TwinCAT.HMI.Server `vers:npm/<14.4.267` | `pkg:tcpkg/beckhoff/TwinCAT.HMI.Server?vers=%3C14.4.267` | `known_affected` |
| TwinCAT.HMI.Server `14.4.267` | `sha256:d62b79b1…` (`.nupkg`), `pkg:tcpkg/…@14.4.267` | `fixed` |
| TF2000-HMI-Server (TwinCAT/BSD) `vers:bsd/<14.4.267` | `pkg:bsd/…?vers=%3C14.4.267` | `known_affected` |
| TF2000-HMI-Server (TwinCAT/BSD) `14.4.267` | `sha256:b1bde82c…` (`.pkg`), `pkg:bsd/…@14.4.267` | `fixed` |
| tf2000-hmi-server (RT Linux ARM64) `vers:deb/<14.4.267` | `pkg:deb/…@14.4.267?arch=arm64&vers=%3C14.4.267` | `known_affected` |
| tf2000-hmi-server (RT Linux ARM64) `14.4.267` | `sha256:0c8612f7…` (`.deb`), `pkg:deb/…@14.4.267?arch=arm64` | `fixed` |
| tf2000-hmi-server (RT Linux AMD64) `vers:deb/<14.4.267` | `pkg:deb/…@14.4.267?arch=amd64&vers=%3C14.4.267` | `known_affected` |
| tf2000-hmi-server (RT Linux AMD64) `14.4.267` | `sha256:cb9fbc60…` (`.deb`), `pkg:deb/…@14.4.267?arch=amd64` | `fixed` |

Only the fixed products carry hashes, so a digest can only confirm a fix.

## Expected (SBOM × CVE-2025-41768)

The SBOM (`sbom/libcrypto.cdx.json`, synthetic despite its name) has three components:

| component | evidence | verdict |
|---|---|---|
| `tf2000-hmi-server-14.4.267` (`pkg:deb/…?arch=amd64`, AMD64 `.deb` hash) | `digest` fixed (1.0); `purl` fixed (1.0) for the AMD64 and the ARM64 statement | fixed, 1.0 |
| `twincat-hmi-server-14.4.267` (`pkg:tcpkg/…@14.4.267`, `.nupkg` hash) | `digest` fixed (1.0); `purl` fixed (1.0) | fixed, 1.0 |
| `unrelated-lib-1.0.0` (all-zero hash) | none | none |

The digest extractor matches both directions (SBOM first, advisory first) with the same evidence
(`extractor/digest.rs`). A digest query matches the bare value under any algorithm, and with an
explicit algorithm only that one (`service/test.rs`, `query_digest`).

## Observations

- **Architecture isn't compared.** The AMD64 component also matches the ARM64 `fixed` statement by
  PURL, because the `arch` qualifier isn't part of the match. The verdict is the same here, but an
  architecture-specific statement would apply to every architecture.
- **Ranges without a known scheme.** There is no `deb` or `bsd` versioning scheme, so
  `vers:deb/<14.4.267` and `vers:bsd/<14.4.267` are stored as `generic`, which only matches equal
  versions. They don't match this SBOM, and they wouldn't match a lower version either. The
  publisher states `vers:npm` for the `tcpkg` package; that range is compared as npm (semver).
- **`vers` as a PURL qualifier.** The affected PURLs carry the range as a `vers` qualifier, which
  isn't a registered qualifier. It is kept as stated; the range used for matching is the one of the
  `product_version_range` branch.

## Files

- SBOM: `sbom/libcrypto.cdx.json` (synthetic)
- Advisory: `vex/vde-2025-106.json` (Beckhoff CSAF via CERT@VDE, TLP:WHITE, as published)
