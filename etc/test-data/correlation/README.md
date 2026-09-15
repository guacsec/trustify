# Correlation Test Data

The files directly under this directory form the public correlation corpus.
Named subdirectories are independent corpora and may define their own cases.

## Coverage Suites

Suites select cases dynamically by tags. A case may belong to multiple suites;
fixtures and expectations are not duplicated. Pending cases remain visible in
the suite output but do not fail the active suite.

| Suite | Priority | Active | Pending | Command |
|---|---:|---:|---:|---|
| `priority0` | 0 | 5 | 5 | `cargo test -p trustify-module-correlation correlation_cases -- --nocapture` |
| `priority1` | 1 | 3 | 1 | `cargo test -p trustify-module-correlation correlation_priority1_cases -- --nocapture` |

### Priority 0

Foundational correlation behavior required for confidence in the core engine: PURL identity, advisory range matching, fixed-version boundaries, supported SBOM format parity, negative matches, and basic advisory aggregation. These cases are the minimum regression gate.

| Case | Status | Coverage |
|---|---|---|
| `public.requests-2026` | Pass | OSV, PURL ranges, fixed boundaries, CycloneDX, SPDX, checksum/CPE negatives |
| `public.urllib3-2026` | Pass | OSV, versionless PURL, fixed boundary, CycloneDX, SPDX |
| `public.aliasless-osv-2022` | Pass | Native GHSA identifier without a CVE alias |
| `public.cve-2026-no-match` | Pass | CVE negative correlation, CycloneDX, SPDX |
| `public.requests-duplicate-2026` | Pass | Duplicate OSV advisories for one vulnerability |
| `public.cpe-2026` | Pending | Public CVE CPE-positive matching |
| `public.csaf-vers-2026` | Pending | Public CSAF VERS/CPE matching |
| `public.csaf-hash-2024` | Pending | Public CSAF product-hash matching |
| `public.cve-requests-2025` | Pending | CVEProject-to-Syft format parity |

### Priority 1

Important breadth beyond the foundation: additional package ecosystems, producers, source formats, duplicate or unusual advisory shapes, and broader product/version behavior. These cases expand confidence but do not define the minimum gate.

| Case | Status | Coverage |
|---|---|---|
| `public.express-2024` | Pass | npm, OSV, PURL ranges, CycloneDX, SPDX |
| `public.urllib3-2026` | Pass | Reused Python ecosystem range case |
| `public.cve-2026-no-match` | Pass | Reused negative CVE case |
| `public.rust-openssl-2026` | Pending | Rust/Cargo OSV range correlation |

## Coverage Status

The public corpus currently covers:

| Behavior | Current coverage |
|---|---|
| OSV PURL range matching | Requests and urllib3 affected/fixed versions |
| Fixed-version boundaries | Requests, urllib3, and Express |
| Versionless PURLs | urllib3 direct component case |
| CycloneDX/SPDX parity | Requests, urllib3, and Express SBOMs |
| Duplicate advisory sources | Duplicate public OSV records for Requests |
| Negative matching | Unrelated public CVEs and checksum/CPE negatives |
| Ecosystem breadth | PyPI and npm, with pending Cargo coverage |

Priority 0 gaps still represented by legacy scenarios or pending cases:

| Gap | Related legacy scenario or case |
|---|---|
| Positive CPE-only matching | `S7_cpeonly_node_hummingbird`, pending `public.cpe-2026` and `public.csaf-vers-2026` |
| Positive checksum/hash matching | Pending `public.csaf-hash-2024` |
| CSAF VERS ranges | `S5a_vers_affected_openssl_el8`, pending `public.csaf-vers-2026` |
| RPM epoch and release boundaries | `S8a_vers_epoch_openjdk` |
| Red Hat stream/substream isolation | `S1a_vers_crossstream_bind-libs`, `S9_substream_openssl_el8` |
| Wrong-product CPE context | `S3a_vers_wrongproduct_hummingbird_curl`, `S4_wrongproduct_satellite_chardet` |
| `known_not_affected` suppression | `S10_combined_describing_cpe`, `S12_notaffected_ignored_thunderbird` |
| Aliasless OSV identifiers | `S13_aliasless_osv_drop` |
| Malformed/degraded PURL identity | Pending `public.degraded-purl-2026` |
| CVEProject advisory identity parity | Pending `public.cve-requests-2025` |
| End-to-end ingestion/API parity | Covered only by legacy `modules/fundamental` tests |

These gaps should be added to the public corpus when suitable external data is
available. Until then, pending cases may remain ignored with an explicit reason.

The suite counts describe behavioral case coverage, not source-code coverage.
Use `cargo llvm-cov` for line and branch coverage.

## OSV-Scanner Validation

The optional `verify-osv.sh` script independently sanity-checks active OSV
cases against public OSV database:

```sh
etc/test-data/correlation/verify-osv.sh
```

Requirements are Bash 4+, `jq`, and OSV-Scanner 2.x. The script was tested with
OSV-Scanner `2.6.0`. By default it requires network access to OSV.dev. Set
`OSV_SCANNER_OFFLINE=1` to use cached local vulnerability databases instead.

This validator is not part of any normal Rust test run and is not the Trustify
correlation oracle. For each artifact-level expectation in an active OSV case,
`affected` IDs must be reported and `none`, `fixed`, or `not_affected` IDs must
be absent. It does not validate direct component expectations or CPE, checksum,
CVE, or CSAF matching.

## Corpus

Tests select one corpus explicitly. Nested corpora do not implicitly participate
in the public corpus. The `subsets` directory contains independent non-public
corpora. Each case directory contains an `expected.json` manifest with
scenario-specific expectations and references to documents from the same
corpus. The tag-based suite manifests live at `priority0.json` and
`priority1.json` in this directory.

## Public 2026 Artifacts

These files were downloaded from public sources on 2026-09-14. The source
checksums are recorded here so updates are intentional and reviewable.

### CVEProject

Source: `https://github.com/CVEProject/cvelistV5`

- `advisories/cve/CVE-2026-12000.json`
  `ddab337152a9974de32d1342dff2760ddd0869ffaa0887fcb9d3d85a40f5f57b`
- `advisories/cve/CVE-2026-12001.json`
  `ee9699231bb9d162def0ccede85bde2e5eed8c74eb0fc886a12f099b12eb8cb3`
- `advisories/cve/CVE-2026-12039.json`
  `4fc1efdfc113825d4ecf9cd4fa647ea4a6c61ce15380fa01575f8b89d00f375a`
- `advisories/cve/CVE-2024-47081.json`
  `d584a4fa3b823d78cc45cceb016cdd0b4014a90ff2ba37a4d26fb3909a200a7b`

### OSV

Source: `https://api.osv.dev/v1/vulns`

- `advisories/osv/PYSEC-2026-1872.json`
  `aaf80fba462800e5f9ab583bc6b633b2f95423c2e27ef821bf5ebd1fef9ad9c8`
- `advisories/osv/PYSEC-2026-1873.json`
  `1d2b345ed0eb3340c7622525e479da8e422d62f4b8633093ae417e1b16155954`
- `advisories/osv/GHSA-gc5v-m9x4-r6x2.json`
  `8bdb5440bd8ce733cb76936fbfbc1a14d9f689a8c76fe638207be9357a80bbe0`
- `advisories/osv/PYSEC-2026-1996.json`
  `28bd7f7649d6f577a4d0ca5995f4feae1d9540b6434ab428fe86d4446ef0783c`
- `advisories/osv/GHSA-8c75-8mhr-p7r9.json`
  `388a6a35c1c54c24eec8cfa1886e1f3ed65eb655f60c1c1613dbe648ddd89c68`
- `advisories/osv/GHSA-9hjg-9r4m-mvj7.json`
  `72e56af89d92cca2f40bd44ae3afa0bc8393cd67d20c67a3d146dde63e685424`
- `advisories/osv/GHSA-qw6h-vgh9-j6wx.json`
  `4275bf6bdc2d5796874d7e5bcd03afa011e9f8d127fe17902660b3a6c4f51bbc`
- `advisories/osv/GHSA-4fx9-vc88-q2xc.json`
  `6af8a2413bcbcede70f0980e9e01554534b87044214a7fbd31bba3c23bd70b44`

### CISA CSAF

Source: `https://github.com/cisagov/CSAF`

- `advisories/csaf/icsa-26-076-01.json`
  `da121b677f4055bc31f656b661080c5be2fba56722a2d6a6277f9e822734f633`
- `advisories/csaf/icsa-24-235-03.json`
  `92b769d532b65e77caec5e7bdb124a65b9f4734a2a495f45e7a8812b77626c52`

### Syft

Source: `https://github.com/anchore/syft/releases/tag/v1.51.1`, published
2026-08-27.

- `sboms/syft/syft-1.51.1-linux-amd64.sbom.json`
  `a7a033d5b31cd8e25f6f93c0cf15a305ab15042d32a9d6b4d4cd3accab6435e9`
- `sboms/syft/syft-1.51.1-darwin-amd64.sbom.json`
  `d74695a4cb44da408229926d7515903093adf8f10b31d2a46787ab52fd5b7c47`

The `requests` CycloneDX and SPDX files were generated with Syft `v1.51.1`
from the public PyPI wheels for Requests `2.32.3` and `2.33.0`.

- `sboms/cyclonedx/requests-2.32.3-syft-1.51.1.cdx.json`
  `27618f95dc6f566602836868e6f6c277c5ed3803351b1d85e19bc2a9ee5ab95c`
- `sboms/cyclonedx/requests-2.33.0-syft-1.51.1.cdx.json`
  `366dcdae647916d838b2471dfdf36f7f7d5068b6a7bd73018fe608c020e0e17b`
- `sboms/spdx/requests-2.32.3-syft-1.51.1.spdx.json`
  `f63ea68f056d8475db3f839fd6c11e71eaaf9bc4b59e1c5525aea6d11f071a94`
- `sboms/spdx/requests-2.33.0-syft-1.51.1.spdx.json`
  `176cc8279f5e9a6e2f89ad83e83c4a7bbcea0d2986776270502ddba3757280c7`
- `sboms/cyclonedx/urllib3-2.6.2-syft-1.51.1.cdx.json`
  `ec2cbee542f728b941daf6e9ff11cd2b6e63c6a07e84781a5b6699aa26508ff5`
- `sboms/cyclonedx/urllib3-2.6.3-syft-1.51.1.cdx.json`
  `5b3183acf2208780151fc556ab8ba72c012458c5638899bd94a3ccb7b7324be4`
- `sboms/spdx/urllib3-2.6.2-syft-1.51.1.spdx.json`
  `6df67bd067edcdd365c30e6a7da5e0cfed42d1e31121346ab160d861eae082e1`
- `sboms/spdx/urllib3-2.6.3-syft-1.51.1.spdx.json`
  `d860723c0880ab97929c5829c5e5f20f0e661df75efcf5e2f52183acdd5f9c4e`
- `sboms/cyclonedx/openssl-0.10.77-syft-1.51.1.cdx.json`
  `08b0f4db0298376ad4029bf292c5d3e442b26f6b968c7020476f40c58ffa9e89`
- `sboms/cyclonedx/openssl-0.10.78-syft-1.51.1.cdx.json`
  `5cc3ce2ba9a7340c20c1f611676cd07715e0adee746430a1f20620966e7a3ccf`
- `sboms/spdx/openssl-0.10.77-syft-1.51.1.spdx.json`
  `8eef1406498e2a9280105e9e2c01257d02f7531a5461eeeafea9ce3212a00daf`
- `sboms/spdx/openssl-0.10.78-syft-1.51.1.spdx.json`
  `e100165de38869071851e03933e02cd01fe794ff803da8b9133956ea54b46220`
- `sboms/cyclonedx/express-4.19.2-syft-1.51.1.cdx.json`
  `a6ac830f7d72688f66a4dadb9f8bcf78e61482803e8462b09a7ae941f52938a2`
- `sboms/cyclonedx/express-4.20.0-syft-1.51.1.cdx.json`
  `02c8de36146073daecf2f0185e39b584e2e344a9c16fca137eed5dab57e22be2`
- `sboms/spdx/express-4.19.2-syft-1.51.1.spdx.json`
  `4a7fbc956f949d85ce16a5c05333d9add762f4c5413a4a5b09aebc753fe84f41`
- `sboms/spdx/express-4.20.0-syft-1.51.1.spdx.json`
  `5e0b42e23712d19fc17345bf24cbfeb9114e17a394002f969d9b6d8b52e3f3f7`

The native Syft release SBOMs are retained as scanner-format fixtures. The
correlation cases use the generated CycloneDX and SPDX artifacts because those
are the SBOM formats currently extracted by `modules/correlation`.

## Running Cases

Run the corpus cases with:

```sh
cargo test -p trustify-module-correlation correlation_cases
```

Current cases:

- `cases/requests-2026/expected.json` checks OSV range resolution for affected
  and fixed Requests releases in both CycloneDX and SPDX, plus direct PURL,
  checksum, and CPE component inputs.
- `cases/urllib3-2026/expected.json` checks another public OSV range across
  affected and fixed urllib3 releases, including a versionless PURL.
- `cases/requests-duplicate-2026/expected.json` checks duplicate public OSV
  records for one vulnerability.
- `cases/aliasless-osv-2022/expected.json` checks a public OSV record using its
  native GHSA identifier without a CVE alias.
- `cases/express-2024/expected.json` checks the npm ecosystem using public
  Express releases before and after the OSV fix.
- `cases/rust-openssl-2026/expected.json` is a pending public Cargo ecosystem
  case for the OSV crates.io range path.
- `cases/cve-2026-no-match/expected.json` checks that unrelated CVE records
  produce `none` verdicts for the Requests SBOMs.
- `cases/cpe-2026/expected.json` is a pending public CPE-positive case. It is
  intentionally ignored until CVE CPE assertions are correlated by the pure
  engine.
- `cases/csaf-vers-2026/expected.json` is a pending public CISA CSAF VERS/CPE
  case.
- `cases/csaf-hash-2024/expected.json` is a pending public CISA CSAF hash case.
- `cases/degraded-purl-2026/expected.json` is a pending malformed-identity
  contract case based on a public OSV advisory.
- `cases/cve-requests-2025/expected.json` is a pending CVE-versus-Syft parity
  case. It is intentionally ignored until CVE package assertions are extracted
  with enough identity information for correlation.
- `cases/csaf-vers-2026/expected.json` is a pending public CISA CSAF VERS/CPE
  case.
- `cases/csaf-hash-2024/expected.json` is a pending public CISA CSAF hash case.

Cases may set `ignored: true` and an `ignore_reason` while the corresponding
engine behavior is being implemented. Active cases run with
`correlation_cases`; pending cases can be exercised explicitly with
`cargo test -p trustify-module-correlation ignored_correlation_cases -- --ignored`.
The suite output reports pass and pending counts. Use `cargo llvm-cov` for
source-code coverage rather than treating case tags as a coverage percentage.

The `priority0` and `priority1` suites dynamically select cases by tags. Cases
may belong to multiple suites without duplicating their data. Run the
additional ecosystem coverage with:

```sh
cargo test -p trustify-module-correlation correlation_priority1_cases -- --nocapture
```
