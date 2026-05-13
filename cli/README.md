# Trustify CLI

A command-line tool for interacting with the [Trustify API](https://github.com/guacsec/trustify). Built for DevSecOps teams who need to keep their software supply chain clean and organized.

## Quick Start

```bash
# Set up your credentials once
cat > .env << EOF
TRUSTIFY_URL=https://trustify.example.com
TRUSTIFY_SSO_URL=https://sso.example.com/realms/trustify
TRUSTIFY_CLIENT_ID=my-client
TRUSTIFY_CLIENT_SECRET=my-secret
EOF

# Find all duplicate SBOMs (same document_id, different versions)
trustify sbom duplicates find

# Preview what would be deleted
trustify sbom duplicates delete --dry-run

# Clean them up!
trustify sbom duplicates delete
```

**Result:** Thousands of duplicate SBOMs cleaned up in seconds with concurrent API requests and automatic retry handling.

## Features

- 🔍 **Duplicate detection** — Find and remove duplicate SBOMs by document ID
- 🔐 **Seamless auth** — OAuth2 with automatic token refresh
- 🔄 **Resilient** — Auto-retry on timeouts and transient failures
- 📦 **SBOM management** — List, get, and delete with flexible output formats

## Index

- [Installation](#installation)
- [Configuration](#configuration)
- [Commands](#commands)
  - [`auth token`](#auth-token)
  - [`sbom list`](#sbom-list)
  - [`sbom get`](#sbom-get-id)
  - [`sbom delete`](#sbom-delete)
  - [`sbom duplicates find`](#sbom-duplicates-find)
  - [`sbom duplicates delete`](#sbom-duplicates-delete)
  - [`sbom prune`](#sbom-prune)
  - [`advisory list`](#advisory-list)
  - [`advisory prune`](#advisory-prune)

- [API Reference](#api-reference)
- [License](#license)

## Installation

### From Source

```bash
cargo install --git https://github.com/guacsec/trustify.git --branch main --path cli 
```

## Configuration

Create a `.env` file in your working directory:

```env
TRUSTIFY_URL=https://trustify.example.com
TRUSTIFY_SSO_URL=https://sso.example.com/realms/trustify
TRUSTIFY_CLIENT_ID=my-client
TRUSTIFY_CLIENT_SECRET=my-secret
```

That's it! The CLI automatically loads credentials and handles OAuth2 token management.

> [!TIP]
> You can also use CLI arguments (`-u`, `--sso-url`, etc.) or shell environment variables. CLI args take priority over env vars, which take priority over `.env` files.

## Commands

### Global Options

```
-u, --url <URL>                      Trustify API URL (required)
    --sso-url <SSO_URL>              SSO URL for authentication
    --client-id <CLIENT_ID>          OAuth2 Client ID
    --client-secret <CLIENT_SECRET>  OAuth2 Client Secret
-h, --help                           Print help
-V, --version                        Print version
```

---

### `auth token`

Get an OAuth2 access token for use with other tools.

```bash
TOKEN=$(trustify auth token)
curl -H "Authorization: Bearer $TOKEN" $TRUSTIFY_URL/api/v3/sbom
```

---

### `sbom get <ID>`

Get an SBOM by ID (returns raw JSON).

```bash
trustify sbom get urn:uuid:abc123
```

---

### `sbom list`

List SBOMs with filtering, pagination, and output formatting.

```bash
trustify sbom list                              # Full JSON
trustify sbom list --format id                  # Just IDs
trustify sbom list --query "name=my-app"        # Filter by name
trustify sbom list --limit 10 --offset 20       # Pagination
trustify sbom list --sort "published:desc"      # Sort by date
```

**Format options:** `id` | `name` | `short` | `full` (default)

---

### `sbom delete`

Delete an SBOM by ID.

```bash
trustify sbom delete --id urn:uuid:abc123
trustify sbom delete --id urn:uuid:abc123 --dry-run  # Preview only
```

---

### `sbom duplicates find`

Scan all SBOMs and find duplicates by `document_id`. Keeps the most recent version, marks others as duplicates.

```bash
trustify sbom duplicates find                   # Default: 4 workers, saves to duplicates.json
trustify sbom duplicates find -j 8              # Faster with 8 concurrent workers
trustify sbom duplicates find -b 500 -j 8       # Larger batches + more workers
trustify sbom duplicates find --output out.json # Custom output file
```

**Output file format:**

```json5
[
  {
    "document_id": "urn:example:sbom-1.0",
    "id": "abc123",                    // ← Keep this one (most recent)
    "published": "2025-01-10T12:00:00Z",
    "duplicates": ["def456", "ghi789"] // ← Delete these
  }
]
```

---

### `sbom duplicates delete`

Delete the duplicates found by `find`. Always preview with `--dry-run` first!

```bash
trustify sbom duplicates delete --dry-run       # Preview what will be deleted
trustify sbom duplicates delete                 # Delete all duplicates
trustify sbom duplicates delete -j 16           # Faster with 16 concurrent requests
trustify sbom duplicates delete --input out.json # Use custom input file
```

---

### `sbom prune`

Prune SBOMs based on various criteria like age, labels, or keeping only the latest versions. Always preview with `--dry-run` first!

```bash
trustify sbom prune --dry-run                                # Preview what will be pruned
trustify sbom prune --older-than 90                          # Delete SBOMs older than 90 days
trustify sbom prune --published-before 2026-01-15T10:30:45Z  # Delete SBOMs published before thespecified date
trustify sbom prune --label type=spdx --label importer=run   # Delete SBOMs with specific labels
trustify sbom prune --keep-latest 5                          # Keep only 5 most recent per document ID
trustify sbom prune --query "name=my-app"                    # Custom query filter
trustify sbom prune --limit 1000                             # Limit results and increase concurrency
trustify sbom prune --output results.json --quiet            # Save results to file, suppress output
```

**Output file format:**

```json5
{
  "deleted": [
    {
      "sbom_id": "urn:uuid:019c4a3f-dc4e-7383-8154-248b6fde0bf0",
      "document_id": "https://security.access.redhat.com/data/sbom/v1/spdx/rhacs-4.9/2026-02-10/789b2d0e8ca41796396188ed277cfc486d11e01c0a38847031afed71ac629729"
    }
  ],
  "deleted_total": 1,
  "skipped": [
    {
      "sbom_id": "urn:uuid:019c4a3f-a277-7882-a7c0-46cc40e6d56d",
      "document_id": "https://security.access.redhat.com/data/sbom/v1/spdx/rhcl-1/2026-02-10/03e360634a6e4c341c198cd526c16f2d2d5a87c24a4d47a224c6234976254272"
    }
  ],
  "skipped_total": 1,
  "failed": [
    {
      "sbom_id": "urn:uuid:019c4a37-0588-7623-bcea-c86b1c934e7f",
      "document_id": "https://security.access.redhat.com/data/sbom/v1/spdx/rhel-9.7.z/2026-02-10/c581247cac636be448ba6a0a931f34a191e626f1d9251d30bb50364b5eee574d",
      "error": "HTTP 408: Server timeout"
    },
    {
      "sbom_id": "urn:uuid:019c4a38-4212-77b3-914e-ed1c897b32d1",
      "document_id": "https://security.access.redhat.com/data/sbom/v1/spdx/rhel-9.6.z/2026-02-10/a149c656d9084b579939ebd4b30b71b3ca5b8ab28c0e39aea00703b274092ea1",
      "error": "HTTP 408: Server timeout"
    },
  ],
  "failed_total": 2,
  "total": 4
}
```

---

### `advisory list`

List advisories with filtering, pagination, and output formatting.

```bash
trustify advisory list                              # Full JSON
trustify advisory list --query "title=CVE-2024-1234"      # Filter by advisory title
trustify advisory list --limit 10 --offset 20       # Pagination
```

---

### `advisory prune`

Prune advisories based on various criteria like age or labels. Always preview with `--dry-run` first!

```bash
trustify advisory prune --dry-run                                # Preview what will be pruned
trustify advisory prune --older-than 90                          # Delete advisories older than 90 days
trustify advisory prune --published-before 2026-01-15T10:30:45Z  # Delete advisories published before the specified date
trustify advisory prune --label type=csaf --label importer=run   # Delete advisories with specific labels
trustify advisory prune --keep-latest 5                          # Keep only 5 most recent per identifier
trustify advisory prune --query "title=CVE-2024-1234"                       # Custom query filter
trustify advisory prune --limit 1000                             # Limit results and increase concurrency
trustify advisory prune --output results.json --quiet            # Save results to file, suppress output
```

**Output file format:**

```json
{
  "deleted": [
    {
      "id": "urn:uuid:7f774d1f-bd19-425c-aa7d-1e35e6d527dc",
      "identifier": "CVE-2019-7589"
    }
  ],
  "deleted_total": 1,
  "skipped": [
    {
      "id": "urn:uuid:3ab23f78-4bf0-44a7-9f1e-2e2bd672643a",
      "identifier": "CVE-2019-7304"
    }
  ],
  "skipped_total": 1,
  "failed": [
    {
      "id": "urn:uuid:abc123",
      "identifier": "CVE-2024-1234",
      "error": "HTTP 408: Server timeout"
    }
  ],
  "failed_total": 1,
  "total": 3
}
```
