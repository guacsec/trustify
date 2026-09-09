# Correlation Engine

Standalone advisory-to-SBOM correlation engine. Matches CSAF, CVE 5.x, and OSV
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

Runs 113 tests including 7 scenario tests (S5-CDX, S6, S7, S8-CDX, S10, S12,
S13). 11 scenarios are ignored with Jira issue references tracking known
limitations.

## Architecture

```
src/
  engine.rs        CorrelationEngine + Collector traits
  collector.rs     Built-in collectors (VecCollector, VerdictCollector, TraceCollector)
  types.rs         StatusAssertion, Verdict, ComponentId, ComponentMatcher
  extract/         Advisory JSON -> Vec<StatusAssertion>
    csaf.rs        CSAF/VEX (product tree walking, Red Hat implied-affected)
    cve.rs         CVE 5.x (version ranges + CPE assertions)
    osv.rs         OSV (affected ranges, ecosystem mapping)
  sbom/            SBOM JSON -> SbomInput
    cyclonedx.rs   CycloneDX component + describing CPE extraction
    spdx.rs        SPDX package + external ref extraction
  version/         Version comparison (ported from PL/pgSQL)
    semver.rs      Lenient semver (also used for npm, golang, gem, etc.)
    rpm.rs         RPM version comparison with epoch handling
    maven.rs       Maven qualifier-aware comparison
    python.rs      PEP 440 comparison
    generic.rs     Exact string equality
  memory/          InMemoryEngine implementation
```
