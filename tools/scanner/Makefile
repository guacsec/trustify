# trustify-scanner
#
# Usage:
#   make help                            Show available targets
#   make build                           Build the scanner binary
#   make scan-sbom SBOM=path/to/sbom.json  Scan an SBOM file
#   make scan-dir DIR=./my-project       Scan a directory
#   make scan-purl PURL=pkg:rpm/redhat/openssl@3.0.7
#   make scan-self                       Scan this repo (Cargo.lock + go.sum)
#
# Environment variables:
#   TRUSTIFY_URL       Trustify API base URL (default: http://localhost:8080)
#   TRUSTIFY_TOKEN     Static bearer token
#   ISSUER_URL         OIDC issuer URL (alternative to TRUSTIFY_TOKEN)
#   CLIENT_ID          OAuth2 client ID
#   CLIENT_SECRET      OAuth2 client secret
#   AUTH_DISABLED       Set to "true" to skip auth

.PHONY: help build test check scan-sbom scan-dir scan-purl scan-self \
        scan-image scan-oci-archive \
        scan-sbom-json scan-zookeeper scan-quarkus \
        scan-example-cdx scan-example-spdx \
        ci-scan clean

# -- Defaults ---------------------------------------------------------------

TRUSTIFY_URL   ?= http://localhost:8080
OUTPUT         ?= table
FAIL_ON        ?=
UPLOAD         ?=
VERBOSE        ?=

# -- Internal ---------------------------------------------------------------

SCANNER := cargo run -p trustify-scanner --

AUTH_ARGS :=
ifdef TRUSTIFY_TOKEN
  AUTH_ARGS += --token $(TRUSTIFY_TOKEN)
else ifdef ISSUER_URL
  AUTH_ARGS += --issuer-url $(ISSUER_URL)
  ifdef CLIENT_ID
    AUTH_ARGS += --client-id $(CLIENT_ID)
  endif
  ifdef CLIENT_SECRET
    AUTH_ARGS += --client-secret $(CLIENT_SECRET)
  endif
endif

BASE := --trustify-url $(TRUSTIFY_URL) $(AUTH_ARGS) -o $(OUTPUT)

ifdef FAIL_ON
  BASE += --fail-on $(FAIL_ON)
endif
ifdef UPLOAD
  BASE += --upload
endif
ifeq ($(VERBOSE),2)
  BASE += -vv
else ifdef VERBOSE
  BASE += -v
endif

TEST_DATA := ../../etc/test-data

# -- Targets ----------------------------------------------------------------

help: ## Show this help
	@grep -E '^[a-z][a-z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk -F ':.*## ' '{printf "  %-24s %s\n", $$1, $$2}'

build: ## Build the scanner binary (release mode)
	cargo build -p trustify-scanner --release

test: ## Run unit tests
	cargo test -p trustify-scanner

check: ## Run clippy, fmt check, and tests
	cargo fmt -p trustify-scanner -- --check
	cargo clippy -p trustify-scanner -- -D warnings
	cargo test -p trustify-scanner

# -- Generic scan entry points -----------------------------------------------

scan-sbom: ## Scan an SBOM file (set SBOM=path/to/file.json)
	$(SCANNER) $(BASE) "sbom:$(SBOM)"

scan-dir: ## Scan a directory (set DIR=./path)
	$(SCANNER) $(BASE) "dir:$(DIR)"

scan-purl: ## Scan a single PURL (set PURL=pkg:type/name@version)
	$(SCANNER) $(BASE) "$(PURL)"

scan-self: ## Scan this repository (auto-detects Cargo.lock, go.sum, etc.)
	$(SCANNER) $(BASE) "dir:../../"

scan-image: ## Scan a container image from registry (set IMAGE=registry/org/name:tag)
	$(SCANNER) $(BASE) "registry:$(IMAGE)"

scan-oci-archive: ## Scan an OCI archive tarball (set ARCHIVE=path/to/image.tar)
	$(SCANNER) $(BASE) "oci-archive:$(ARCHIVE)"

# -- Test data SBOM scans ---------------------------------------------------

scan-zookeeper: ## Scan the zookeeper CycloneDX test SBOM
	$(SCANNER) $(BASE) "sbom:$(TEST_DATA)/zookeeper-3.9.2-cyclonedx.json"

scan-quarkus: ## Scan the quarkus-bom SPDX test SBOM
	$(SCANNER) $(BASE) "sbom:$(TEST_DATA)/quarkus-bom-2.13.8.Final-redhat-00004.json"

scan-example-cdx: ## Scan the CycloneDX application example SBOM
	$(SCANNER) $(BASE) "sbom:$(TEST_DATA)/cyclonedx/application.cdx.json"

scan-example-spdx: ## Scan an SPDX test SBOM (OCP TOOLS)
	$(SCANNER) $(BASE) "sbom:$(TEST_DATA)/spdx/OCP-TOOLS-4.11-RHEL-8.json"

# -- JSON output variants ---------------------------------------------------

scan-sbom-json: ## Scan an SBOM and output JSON (set SBOM=path)
	$(SCANNER) $(BASE) -o json "sbom:$(SBOM)"

scan-zookeeper-json: ## Scan zookeeper SBOM with JSON output
	$(SCANNER) $(BASE) -o json "sbom:$(TEST_DATA)/zookeeper-3.9.2-cyclonedx.json"

# -- CI integration ----------------------------------------------------------

ci-scan: ## CI scan: fail on high severity (set SBOM or DIR)
ifdef SBOM
	$(SCANNER) $(BASE) --fail-on high "sbom:$(SBOM)"
else ifdef DIR
	$(SCANNER) $(BASE) --fail-on high "dir:$(DIR)"
else
	@echo "ERROR: set SBOM=path or DIR=path"; exit 1
endif

# -- Housekeeping ------------------------------------------------------------

clean: ## Remove build artifacts
	cargo clean -p trustify-scanner
