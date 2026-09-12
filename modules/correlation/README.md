# Correlation Pipeline

Standalone advisory-to-SBOM correlation pipeline. Matches CSAF, CVE 5.x, and OSV
advisories against CycloneDX/SPDX SBOMs to determine vulnerability status per
component, without requiring a database.

## Web UI

A browser-based demo is included under `examples/wasm-ui/`. It compiles the
engine to WebAssembly and runs entirely client-side.

### Prerequisites

```sh
rustup target add wasm32-unknown-unknown
cargo install trunk
```

### Run

```sh
cd modules/correlation/examples/wasm-ui
trunk serve --open
```

This builds the WASM binary and opens the app in your browser. From there:

1. Drop one or more advisory files onto the advisory drop zone (`.json` or
   `.json.xz` — CSAF, CVE, or OSV format).
2. Switch between **PURL Query** (enter a single package URL) and **SBOM
   Correlation** (drop a CycloneDX or SPDX SBOM file).
3. Click **Correlate** to run the engine and see verdicts.
4. Expand **Decision Trace** for a step-by-step explanation of matching
   decisions.

### Try it with a scenario

The test scenarios under `etc/test-data/scenarios/` include advisories and SBOMs
that work together. For example, to test S6:

```sh
# Start the UI
cd modules/correlation/examples/wasm-ui
trunk serve --open
```

Then in the browser:

1. Drop `etc/test-data/scenarios/S6_positive_baseline_osv_urllib3/GHSA-v845-jxx5-vc9f.json`
   onto the advisory zone.
2. Switch to SBOM Correlation and drop
   `etc/test-data/scenarios/S6_positive_baseline_osv_urllib3/sbom_urllib3.cdx.json`.
3. Click Correlate — you should see CVE-2023-45803 as **affected**.

## Tests

```sh
cargo test -p trustify-module-correlation
```

Runs the unit and scenario suite. Scenarios that describe known limitations are
ignored with Jira issue references.

## Example

Run the complete normalized flow with one advisory and one SBOM:

```sh
cargo run -p trustify-module-correlation --example correlate -- advisory.json sbom.json
```

The example extracts `AdvisoryEvidence` and `SbomEvidence`, joins them into
`Evidence`, and passes that complete input to `engine::correlate` to obtain
owned verdicts.

## Architecture

```
src/
  extract/         Raw advisory/SBOM documents -> normalized evidence
    advisory/      Advisory extraction peer
      csaf.rs      CSAF/VEX (product tree walking, version policies)
      cve.rs       CVE 5.x (version ranges + CPE assertions)
      osv.rs       OSV (affected ranges, ecosystem mapping)
    sbom/          SBOM extraction peer
      cyclonedx.rs CycloneDX components, metadata context, dependencies
      spdx.rs      SPDX packages, describing relationships, dependencies
  evidence.rs      AdvisoryEvidence + SbomEvidence -> Evidence input
  verdict.rs       Verdict type exports
  engine.rs        Stateless correlate function + Collector contract
  collector.rs     Built-in collectors (VecCollector, VerdictCollector, TraceCollector)
  matching.rs       Identity and applicability matching
  resolution.rs    Deterministic verdict resolution
  types.rs         Shared assertion, identity, context, and verdict vocabulary
  version/         Version comparison (ported from PL/pgSQL)
    semver.rs      Lenient semver (also used for npm, golang, gem, etc.)
    rpm.rs         RPM version comparison with epoch handling
    maven.rs       Maven qualifier-aware comparison
    python.rs      PEP 440 comparison
    generic.rs     Exact string equality
  memory/          AdvisoryIndex
```
