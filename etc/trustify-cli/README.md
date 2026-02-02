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
- [API Reference](#api-reference)
- [License](#license)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/ruromero/trustify-cli.git
cd trustify-cli

# Build
cargo build --release

# The binary will be at ./target/release/trustify
```

### Using Docker

```bash
# Use your .env file with the container
docker run --rm --env-file .env ghcr.io/ruromero/trustify-cli sbom list

# For commands that write files, mount a volume
docker run --rm --env-file .env -v $(pwd):/data \
  ghcr.io/ruromero/trustify-cli sbom duplicates find --output /data/duplicates.json
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

> **Tip:** You can also use CLI arguments (`-u`, `--sso-url`, etc.) or shell environment variables. CLI args take priority over env vars, which take priority over `.env` files.

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
curl -H "Authorization: Bearer $TOKEN" $TRUSTIFY_URL/api/v2/sbom
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

```json
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
