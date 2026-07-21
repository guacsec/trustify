# trustify-scanner: Architecture and Plan

## Overview

A Rust CLI tool that scans a target (directory, container image, or SBOM file),
discovers software packages, constructs an interim CycloneDX SBOM, and submits
the extracted PURLs to the trustify backend for vulnerability analysis.

Conceptually: **syft (package discovery) + grype (vuln matching)**, but with
trustify as the vulnerability data source instead of a local database.

```
 +-----------+      +------------------+      +------------------+
 |  Target   | ---> | Package Discovery| ---> | CycloneDX SBOM   |
 | dir/image |      | (catalogers)     |      | (interim)        |
 | /sbom     |      +------------------+      +--------+---------+
 +-----------+                                         |
                                                       v
                                              +--------+---------+
                                              | Extract PURLs    |
                                              +--------+---------+
                                                       |
                                                       v
                                              +--------+---------+
                                              | POST /v3/        |
                                              | vulnerability/   |
                                              | analyze           |
                                              +--------+---------+
                                                       |
                                                       v
                                              +--------+---------+
                                              | Format & Output  |
                                              | (table/json/     |
                                              |  cyclonedx/sarif) |
                                              +------------------+
```

## Scan Targets

### Phase 1 (MVP)

| Target | CLI syntax | Discovery method |
|--------|-----------|-----------------|
| SBOM file | `trustify-scanner sbom:path.json` | Parse SPDX or CycloneDX, extract existing PURLs |
| Directory | `trustify-scanner dir:./path` | Walk filesystem, run catalogers |
| Single PURL | `trustify-scanner pkg:rpm/redhat/openssl@3.0.7` | Direct analysis, no discovery needed |

### Phase 2

| Target | CLI syntax | Discovery method |
|--------|-----------|-----------------|
| Container image (registry) | `trustify-scanner registry:image:tag` | Pull via OCI, extract layers, run catalogers |
| Container image (local) | `trustify-scanner docker:image:tag` | Read from Docker daemon, extract layers, run catalogers |
| OCI archive | `trustify-scanner oci-archive:file.tar` | Unpack layers, run catalogers |

## CLI Interface

```
trustify-scanner [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Scan target (dir:PATH, sbom:PATH, registry:IMAGE, pkg:PURL)

Options:
  --trustify-url <URL>     Trustify API base URL [env: TRUSTIFY_URL]
  --token <TOKEN>          Bearer token [env: TRUSTIFY_TOKEN]
  --issuer-url <URL>       OIDC issuer URL for client_credentials [env: ISSUER_URL]
  --client-id <ID>         OAuth2 client ID [env: CLIENT_ID]
  --client-secret <SEC>    OAuth2 client secret [env: CLIENT_SECRET]
  -o, --output <FORMAT>    Output format: table (default), json, cyclonedx-json, sarif
  --fail-on <SEVERITY>     Exit 1 if vulnerabilities at or above severity (low/medium/high/critical)
  --upload                 Also upload the generated SBOM to trustify
  --recommend              Include patched version recommendations (calls /v3/purl/recommend)
  -q, --quiet              Suppress progress output
  -v, --verbose            Increase verbosity (repeatable)
```

## Architecture

### Crate Structure

```
tools/scanner/
  Cargo.toml               # Binary crate, workspace member
  docs/
    architecture.md         # This file
  src/
    main.rs                 # CLI entry point (clap)
    target.rs               # Target enum and parser (dir, sbom, registry, purl)
    auth.rs                 # OIDC token provider (client_credentials grant)
    client.rs               # Trustify API client (reqwest)
    cataloger/
      mod.rs                # Cataloger trait and registry
      cargo.rs              # Cargo.lock parser
      npm.rs                # package-lock.json parser
      go.rs                 # go.sum / go.mod parser
      python.rs             # requirements.txt / poetry.lock / Pipfile.lock
      rpm.rs                # RPM database parser
      dpkg.rs               # dpkg status parser
      maven.rs              # pom.xml parser
      sbom.rs               # SPDX / CycloneDX passthrough
    sbom.rs                 # CycloneDX SBOM builder from discovered packages
    analyze.rs              # Orchestrate: discover -> build SBOM -> call API -> format
    output/
      mod.rs                # Output trait and dispatcher
      table.rs              # Human-readable table
      json.rs               # JSON output
      cyclonedx.rs           # CycloneDX with vulnerability annotations
      sarif.rs              # SARIF for CI/CD integration
    error.rs                # Error enum (thiserror)
    container.rs            # OCI image pull and layer extraction (Phase 2)
```

### Key Types

```rust
/// A discovered package from a cataloger.
struct DiscoveredPackage {
    purl: Purl,
    name: String,
    version: String,
    source: PackageSource,  // Which cataloger / file found it
    locations: Vec<PathBuf>,
}

/// Cataloger trait: discovers packages from a filesystem tree.
trait Cataloger: Send + Sync {
    /// Files this cataloger is interested in (glob patterns).
    fn globs(&self) -> &[&str];

    /// Discover packages from the matched files.
    fn catalog(&self, root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error>;
}

/// Scan result combining trustify API response with local context.
struct ScanResult {
    target: String,
    packages: Vec<DiscoveredPackage>,
    vulnerabilities: Vec<VulnerabilityMatch>,
    recommendations: Option<HashMap<String, Vec<RecommendEntry>>>,
}

/// A vulnerability matched to a specific package.
struct VulnerabilityMatch {
    package: DiscoveredPackage,
    vulnerability_id: String,
    title: Option<String>,
    severity: Option<String>,
    score: Option<f64>,
    status: String,
    advisory: String,
    fixed_in: Option<String>,
}
```

### Core Flow

```rust
async fn scan(target: Target, config: Config) -> Result<ScanResult> {
    // 1. Discover packages
    let packages = match target {
        Target::Sbom(path) => cataloger::sbom::catalog(&path)?,
        Target::Dir(path) => run_catalogers(&path)?,
        Target::Purl(purl) => vec![DiscoveredPackage::from_purl(purl)],
        Target::Registry(image) => {
            let layers = container::pull_and_extract(&image).await?;
            run_catalogers(&layers)?
        }
    };

    // 2. Build interim CycloneDX SBOM
    let sbom = build_cyclonedx(&packages)?;

    // 3. Extract PURLs (only versioned ones)
    let purls: Vec<String> = packages
        .iter()
        .filter(|p| p.purl.version.is_some())
        .map(|p| p.purl.to_string())
        .collect();

    // 4. Call trustify vulnerability analysis
    let client = TrustifyClient::new(&config)?;
    let analysis = client.analyze_vulnerabilities(&purls).await?;

    // 5. Optionally get recommendations
    let recommendations = if config.recommend {
        Some(client.recommend_purls(&purls).await?)
    } else {
        None
    };

    // 6. Optionally upload the SBOM
    if config.upload {
        client.upload_sbom(&sbom).await?;
    }

    // 7. Assemble results
    Ok(assemble_results(packages, analysis, recommendations))
}
```

## Trustify API Usage

### Primary: `POST /api/v3/vulnerability/analyze`

The main vulnerability matching endpoint. Accepts a list of versioned PURLs and
returns vulnerabilities grouped by input PURL.

- **Request:** `{ "purls": ["pkg:rpm/redhat/openssl@3.0.7", ...] }`
- **Response:** Map of PURL -> vulnerabilities with advisory details, CVSS scores,
  version ranges, and remediation info.
- **Batching:** The API accepts multiple PURLs in a single call. For large SBOMs
  (1000+ packages), batch into chunks of ~500 PURLs to avoid request timeouts.
- **Auth:** Requires `ReadAdvisory` permission.

### Secondary: `POST /api/v3/purl/recommend`

Returns patched version recommendations (Red Hat-specific: finds the highest
Red Hat patch version matching the input's major.minor.patch).

- **Request:** `{ "purls": [<Purl objects>] }`
- **Response:** Map of PURL -> recommended versions with their vulnerability status.
- **Auth:** Requires `ReadAdvisory` permission.

### Optional: `POST /api/v3/sbom`

Upload the generated SBOM to trustify for persistent tracking.

- **Request:** Raw SBOM bytes (CycloneDX JSON), auto-detected format.
- **Response:** `{ "id": "urn:uuid:...", "document_id": "...", "warnings": [] }`
- **Auth:** Requires `CreateSbom` permission.

### Not used: `POST /api/v3/ui/extract-sbom-purls`

This endpoint extracts PURLs from an SBOM file server-side. We skip it because
the scanner already parses SBOMs locally (via the sbom cataloger), which avoids
an extra network round-trip and works offline except for the final analysis call.

## Catalogers (Phase 1 Priority)

Ordered by expected prevalence in Red Hat / Konflux builds:

| Priority | Ecosystem | File patterns | PURL type | Crate |
|----------|----------|--------------|-----------|-------|
| P0 | SBOM passthrough | `*.json`, `*.spdx`, `*.cdx.json` | any | `cyclonedx-bom`, `spdx-rs` |
| P1 | RPM | `/var/lib/rpm/Packages*`, `*.rpm` | `pkg:rpm` | `rpm` crate |
| P1 | Go | `go.mod`, `go.sum` | `pkg:golang` | Custom parser |
| P1 | Maven | `pom.xml` | `pkg:maven` | `quick-xml` |
| P2 | npm | `package-lock.json` | `pkg:npm` | `serde_json` |
| P2 | Cargo | `Cargo.lock` | `pkg:cargo` | `cargo-lock` |
| P2 | Python | `requirements.txt`, `poetry.lock`, `Pipfile.lock` | `pkg:pypi` | Custom / `serde` |
| P3 | dpkg | `/var/lib/dpkg/status` | `pkg:deb` | `oma-debcontrol` |
| P3 | Gem | `Gemfile.lock` | `pkg:gem` | Custom parser |
| P3 | NuGet | `packages.lock.json` | `pkg:nuget` | `serde_json` |

## Container Image Support (Phase 2)

Use `oci-client` + `oci-spec` to pull OCI images from registries.

Flow:
1. Resolve image reference to a manifest (handle multi-arch index).
2. Pull layer blobs (gzipped tar).
3. Extract layers into a temp directory (respecting whiteout files).
4. Run catalogers against the extracted filesystem.
5. Clean up temp directory.

For local Docker daemon images, use `bollard` to export the image as a tar
stream and process layers from that.

## Output Formats

### Table (default)

```
NAME            INSTALLED   FIXED-IN    TYPE   VULNERABILITY   SEVERITY   SCORE
openssl         3.0.7       3.0.13      rpm    CVE-2024-0727   Medium     5.5
curl            8.4.0                   rpm    CVE-2024-2398   High       7.5
```

### JSON

Structured output matching the trustify analysis response, enriched with
package source/location metadata from discovery.

### CycloneDX JSON

A CycloneDX BOM with `vulnerabilities` array populated from trustify results.
Suitable for ingestion by other tools or archival.

### SARIF

Static Analysis Results Interchange Format for CI/CD integration
(GitHub Code Scanning, Azure DevOps, etc.).

## Dependencies (New Workspace Additions)

| Crate | Purpose | Version |
|-------|---------|---------|
| `clap` | CLI argument parsing | (already in workspace) |
| `reqwest` | HTTP client for trustify API | (already in workspace) |
| `cyclonedx-bom` | CycloneDX SBOM generation | latest stable |
| `packageurl` | PURL construction/parsing | latest stable |
| `cargo-lock` | Cargo.lock parsing | latest stable |
| `rpm` | RPM package parsing | latest stable |
| `oci-client` | OCI image pulling (Phase 2) | latest stable |
| `oci-spec` | OCI spec types (Phase 2) | latest stable |
| `comfy-table` | Terminal table formatting | latest stable |
| `serde_sarif` | SARIF output (if available) | latest stable |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no vulnerabilities at or above `--fail-on` threshold |
| 1 | Scan completed, vulnerabilities found at or above `--fail-on` threshold |
| 2 | Scan failed (network error, auth error, parse error) |

## Open Questions

1. **Offline mode?** Should the scanner work without a trustify instance
   (e.g., using a local advisory cache)? Initial answer: no, trustify
   connectivity is required.

2. **SBOM-only mode?** Should `trustify-scanner sbom:file.json` also support
   sending the SBOM to `POST /api/v3/ui/extract-sbom-purls` instead of parsing
   locally? Could be useful if the server-side parser handles formats the local
   parser doesn't. Initial answer: no

3. **Incremental scanning?** Should the scanner cache previous results and only
   re-analyze changed packages? Likely out of scope for MVP. Initial answer: out of scope

4. **VEX integration?** Should the scanner accept VEX documents to suppress
   known false positives? Trustify already applies VEX server-side via advisory
   statuses (not_affected, fixed), so this may be unnecessary.

5. **Multi-arch container scanning?** When scanning a multi-arch image index,
   should we scan all architectures or just the host arch? Default to host arch,
   allow `--platform` override.

6. **Rate limiting?** For large SBOMs generating thousands of PURLs, should we
   implement client-side rate limiting or rely on trustify's server-side limits? yes with 
   reasonable defaults.

## Implementation Plan

### Milestone 1: MVP (SBOM + directory scan, table output)

1. Set up crate structure, workspace member, `clap` CLI
2. Implement trustify API client (`client.rs`, `auth.rs`)
3. Implement SBOM cataloger (parse SPDX/CycloneDX, extract PURLs)
4. Implement PURL target (direct analysis, no discovery)
5. Implement table output formatter
6. Implement directory scanning with Cargo.lock + go.mod catalogers
7. Wire up the full scan flow (`analyze.rs`)

### Milestone 2: Full cataloger coverage

8. Add RPM cataloger
9. Add npm cataloger
10. Add Maven cataloger
11. Add Python cataloger
12. Add remaining catalogers (dpkg, gem, nuget)

### Milestone 3: Output formats + container support

13. Add JSON output
14. Add CycloneDX output with vulnerabilities
15. Add SARIF output
16. Implement OCI image pulling and layer extraction
17. Wire up container scanning flow

### Milestone 4: Polish

18. Add `--recommend` flag (purl/recommend API)
19. Add `--upload` flag (SBOM upload to trustify)
20. Add `--fail-on` severity threshold
21. Error handling polish, user-facing messages
22. Integration tests against a real trustify instance
