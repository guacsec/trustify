# trustify-scanner

A vulnerability scanner CLI that discovers software packages in a target
(directory, SBOM file, container image, or bare PURL) and checks them against a
[trustify](https://github.com/trustification/trustify) backend for known
vulnerabilities.

Conceptually similar to [grype](https://github.com/anchore/grype), but uses
trustify as the vulnerability data source instead of a local database.

## Quick start

```sh
# Build
cargo build -p trustify-scanner

# Run tests
cargo test -p trustify-scanner

# Scan an SBOM
trustify-scanner --trustify-url http://localhost:8080 sbom:my-sbom.json

# Scan a project directory
trustify-scanner --trustify-url http://localhost:8080 dir:./my-project

# Scan a single package
trustify-scanner --trustify-url http://localhost:8080 pkg:rpm/redhat/openssl@3.0.7

# Scan a container image from a registry
trustify-scanner --trustify-url http://localhost:8080 registry:registry.access.redhat.com/ubi9:latest

# Scan an OCI archive
trustify-scanner --trustify-url http://localhost:8080 oci-archive:image.tar

# Auto-detect (file -> SBOM, directory -> dir scan, image-like -> registry)
trustify-scanner --trustify-url http://localhost:8080 ./my-project
trustify-scanner --trustify-url http://localhost:8080 quay.io/redhat/ubi9:latest
```

## Example output

```
 ✔ Scanned for vulnerabilities     [22 vulnerability matches]
   ├── by severity: 22 unknown
   └── 41 packages scanned, 41 analyzed (sbom)
NAME                           INSTALLED            TYPE           VULNERABILITY         SEVERITY   STATUS
logback-core                   1.2.13               maven          CVE-2024-12798                   affected
logback-core                   1.2.13               maven          CVE-2024-12801                   affected
commons-io                     2.11.0               maven          CVE-2024-47554                   affected
netty-codec                    4.1.105.Final        maven          CVE-2025-58057                   affected
netty-common                   4.1.105.Final        maven          CVE-2024-47535                   affected
zookeeper                      3.9.2                maven          CVE-2024-51504                   affected
jetty-server                   9.4.53.v20231009     maven          CVE-2024-8184                    affected
```

When no packages are found (e.g. scanning a C project):

```
 ⚠ No packages discovered          [nothing to analyze]
   ├── no recognized dependency files found
   └── supported files: Cargo.lock, go.sum, package-lock.json, requirements.txt,
       pyproject.toml, uv.lock, poetry.lock, Pipfile.lock, gradle.lockfile, *.rpm
```

## Scan targets

| Target | Syntax | Description |
|--------|--------|-------------|
| SBOM file | `sbom:path.json` | Parse SPDX (2.x and 3.x) or CycloneDX JSON, extract PURLs |
| Directory | `dir:./path` | Walk filesystem, discover packages via catalogers |
| Package URL | `pkg:type/name@version` | Analyze a single PURL directly |
| Container image | `registry:image:tag` | Pull from OCI registry, extract layers, run catalogers |
| OCI archive | `oci-archive:path.tar` | Unpack local OCI tarball, extract layers, run catalogers |
| Auto-detect | `./path` | File -> SBOM, directory -> dir scan |
| Auto-detect | `quay.io/org/img:tag` | Image-like references (containing `/`) -> registry |

## Supported ecosystems

When scanning a directory, the following dependency files are recognized:

| Ecosystem | Files | PURL type |
|-----------|-------|-----------|
| Rust | `Cargo.lock` | `pkg:cargo` |
| Go | `go.sum` | `pkg:golang` |
| npm | `package-lock.json` (v1, v2, v3) | `pkg:npm` |
| Python | `requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `Pipfile.lock` | `pkg:pypi` |
| Java | `gradle.lockfile` | `pkg:maven` |
| RPM | `*.rpm` | `pkg:rpm` |

When scanning an SBOM file, the following formats are supported:

| Format | Detection |
|--------|-----------|
| SPDX 2.x JSON | `spdxVersion` key; PURLs from `externalRefs` |
| SPDX 3.x JSON-LD | `@graph` array; PURLs from `externalIdentifier` |
| CycloneDX JSON | `bomFormat` key; PURLs from `purl` field on components |

## Output formats

| Format | Flag | Description |
|--------|------|-------------|
| List | `-o list` (default) | Compact grype-style list with severity summary |
| Table | `-o table` | Bordered table with score, status, and advisory columns |
| JSON | `-o json` | Structured JSON for programmatic consumption |

## Verbose mode

Use `-v` to see discovered packages grouped by ecosystem type:

```sh
trustify-scanner --trustify-url $URL -v sbom:my-sbom.json
```

```
 ✔ Scanned for vulnerabilities     [5 vulnerability matches]
   ├── by severity: 2 high, 3 medium
   └── 41 packages scanned, 41 analyzed (sbom)

Discovered packages (41 total):
  maven (38):
    pkg:maven/io.netty/netty-common@4.1.105.Final
    pkg:maven/io.netty/netty-handler@4.1.105.Final
    pkg:maven/commons-io/commons-io@2.11.0
    ... and 35 more
  golang (3):
    pkg:golang/github.com/foo/bar@1.2.3
    pkg:golang/golang.org/x/net@0.19.0
    pkg:golang/golang.org/x/text@0.14.0
```

| Flag | Detail level |
|------|-------------|
| `-v` | All discovered PURLs grouped by type |
| `-vv` | All PURLs + debug-level tracing |

## Authentication

The scanner supports three authentication modes:

```sh
# Static bearer token
trustify-scanner --trustify-url $URL --token $TOKEN sbom:file.json

# OIDC client_credentials grant
trustify-scanner --trustify-url $URL \
  --issuer-url https://sso.example.com/realms/trustify \
  --client-id scanner \
  --client-secret secret123 \
  sbom:file.json

# No auth (for --auth-disabled instances)
trustify-scanner --trustify-url $URL sbom:file.json
```

All auth options can also be set via environment variables:
`TRUSTIFY_URL`, `TRUSTIFY_TOKEN`, `ISSUER_URL`, `CLIENT_ID`, `CLIENT_SECRET`.

## Security

The scanner applies several defensive measures when processing untrusted inputs:

- **Symlink traversal disabled by default** -- directory walks do not follow
  symlinks unless `--follow-links` is explicitly passed, preventing reads
  outside the scan root.
- **File size limit** -- dependency files larger than 256 MiB are rejected
  to prevent OOM on malicious inputs.
- **CycloneDX recursion depth limit** -- nested component trees are capped at
  64 levels to prevent stack overflow.
- **Container extraction size limit** -- extracted layer content is capped at
  2 GiB total to prevent disk exhaustion.
- **Tar path traversal prevention** -- tar entries containing `..` path
  components are rejected during container layer extraction.
- **OCI whiteout handling** -- `.wh.*` deletion markers in container layers
  are processed correctly.
- **UTF-8 safe output** -- string truncation operates on character boundaries,
  not bytes.

## CI/CD integration

Use `--fail-on` to exit with code 1 when vulnerabilities at or above a severity
threshold are found. Matches on both numeric CVSS score and severity string
(for advisories that lack scores):

```sh
trustify-scanner --trustify-url $URL --fail-on high sbom:my-sbom.json
```

| Exit code | Meaning |
|-----------|---------|
| 0 | Scan completed, no vulnerabilities at or above threshold |
| 1 | Vulnerabilities found at or above `--fail-on` threshold |
| 2 | Scan failed (network error, auth error, parse error) |

## Makefile

A Makefile is provided for common operations. Run from the `tools/scanner/` directory:

```sh
make help                                    # Show all targets
make test                                    # Run unit tests
make check                                   # Run fmt + clippy + tests
make build                                   # Release build
make scan-sbom SBOM=path/to/sbom.json        # Scan an SBOM
make scan-dir DIR=./my-project               # Scan a directory
make scan-purl PURL=pkg:rpm/redhat/openssl@3.0.7
make scan-image IMAGE=registry.access.redhat.com/ubi9:latest
make scan-oci-archive ARCHIVE=image.tar      # Scan OCI archive
make scan-self                               # Scan this repo
make scan-zookeeper                          # Scan test SBOM
make ci-scan SBOM=sbom.json                  # CI mode (fail on high)
```

Override defaults via environment or make variables:

```sh
make scan-self TRUSTIFY_URL=https://trustify.example.com TRUSTIFY_TOKEN=tok123
make scan-zookeeper OUTPUT=json
make scan-self VERBOSE=1                     # Show all discovered PURLs
make scan-self VERBOSE=2                     # PURLs + debug tracing
```

## How it works

```
Target (dir/sbom/purl/container)
  │
  ▼
Package Discovery ─── catalogers walk the filesystem and parse lockfiles
  │                   (for containers: pull image, extract layers, then catalog)
  ▼
Extract PURLs ──────── collect versioned Package URLs from discovered packages
  │
  ▼
POST /api/v3/vulnerability/analyze ── send PURLs to trustify in batches of 500
  │
  ▼
Format & Output ──── render results as list, table, or JSON
```

For container targets, the scanner pulls the OCI image manifest from the
registry, downloads each filesystem layer (gzipped tar), extracts them into
a temporary directory (handling OCI whiteout files for deletions), then runs
the standard catalogers against the extracted filesystem. The temporary
directory is cleaned up automatically after scanning completes.

The scanner does not maintain a local vulnerability database. All vulnerability
matching is performed server-side by the trustify instance, which matches PURLs
against ingested advisories (CSAF, OSV/GHSA, CVE, etc.) using version range
comparisons.

## Options reference

```
trustify-scanner [OPTIONS] --trustify-url <URL> <TARGET>

Arguments:
  <TARGET>              Scan target (dir:PATH, sbom:PATH, pkg:PURL,
                        registry:IMAGE, oci-archive:PATH, or plain path)

Options:
      --trustify-url    Trustify API base URL [env: TRUSTIFY_URL]
      --token           Static bearer token [env: TRUSTIFY_TOKEN]
      --issuer-url      OIDC issuer URL [env: ISSUER_URL]
      --client-id       OAuth2 client ID [env: CLIENT_ID]
      --client-secret   OAuth2 client secret [env: CLIENT_SECRET]
  -o, --output          Output format: list (default), table, json
      --fail-on         Exit 1 if vulns >= severity: low, medium, high, critical
      --upload          Also upload the generated SBOM to trustify
      --follow-links    Follow symbolic links when scanning directories
  -v, --verbose         Increase verbosity (-v, -vv, -vvv)
  -h, --help            Print help
  -V, --version         Print version
```
