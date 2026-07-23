# Trustify Gate - CI/CD Policy Gate
#
# Usage:
#   make check SBOM=path/to/sbom.json                  Check a local SBOM (extract PURLs, analyze)
#   make check-upload SBOM=path/to/sbom.json            Upload SBOM then check
#   make check-name NAME="my-product-1.0"               Check an already-ingested SBOM by name
#   make check-id ID=urn:uuid:...                       Check an already-ingested SBOM by ID
#   make list-checkers                                  List available checker plugins
#   make sync                                           Install dependencies

.PHONY: check check-upload check-name check-id list-checkers sync

TRUSTIFY_URL ?= http://localhost:8080
CONFIG ?=
FORMAT ?= table

# Optional --config flag.
_CONFIG_FLAG = $(if $(CONFIG),--config $(CONFIG),)

check: ## Check a local SBOM file
	TRUSTIFY_URL=$(TRUSTIFY_URL) uv run python gate.py check --sbom $(SBOM) $(_CONFIG_FLAG) --format $(FORMAT)

check-upload: ## Upload SBOM to Trustify then check
	TRUSTIFY_URL=$(TRUSTIFY_URL) uv run python gate.py check --sbom $(SBOM) --upload $(_CONFIG_FLAG) --format $(FORMAT)

check-name: ## Check an SBOM already in Trustify (by name)
	TRUSTIFY_URL=$(TRUSTIFY_URL) uv run python gate.py check --sbom-name "$(NAME)" $(_CONFIG_FLAG) --format $(FORMAT)

check-id: ## Check an SBOM already in Trustify (by ID)
	TRUSTIFY_URL=$(TRUSTIFY_URL) uv run python gate.py check --sbom-id "$(ID)" $(_CONFIG_FLAG) --format $(FORMAT)

list-checkers: ## List available checker plugins
	uv run python gate.py list-checkers

sync: ## Install dependencies
	uv sync
