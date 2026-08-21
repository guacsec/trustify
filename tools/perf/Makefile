# Trustify Locust performance tests
#
# Usage:
#   make help                    Show available targets
#   make test                    Run all v3 tests (5m, 10 users)
#   make test-readonly           Run only read-only v3 tests
#   make test-advisory           Run v3 advisory tests only
#   make test HOST=my-host:8080  Override target host
#
# All TOOLS_PERF_* env vars are forwarded automatically.

.PHONY: help test test-v3 test-v2 test-all \
        test-readonly test-readonly-v2 test-readonly-all \
        test-advisory test-vulnerability test-sbom test-purl \
        test-product test-organization test-importer test-license \
        test-weakness test-group test-misc \
        test-analysis-v3 test-analysis-v2 \
        test-slow-v3 test-labels-v3 \
        test-website ui clean

# -- Defaults (override on command line or via env) -------------------------

HOST          ?= http://localhost:8080
USERS         ?= 10
SPAWN_RATE    ?= 2
DURATION      ?= 5m
SCENARIO_FILE ?=

# -- Internal ---------------------------------------------------------------

LOCUST    := uv run locust
TIMESTAMP := $(shell date +%Y%m%dT%H%M%S)

# run_prefix(target) -- generates the base path for report outputs:
#   reports/v3-readonly_u10_5m_20260729T143022
# Locust appends .html for --html and _stats.csv / _stats_history.csv /
# _failures.csv / _exceptions.csv for --csv.
run_prefix = reports/$(1)_u$(USERS)_$(DURATION)_$(TIMESTAMP)

# BASE is constructed per-target using $(call run_prefix,<target>)
define BASE
--host $(HOST) -u $(USERS) -r $(SPAWN_RATE) -t $(DURATION) \
--headless --html=$(call run_prefix,$(1)).html --csv=$(call run_prefix,$(1))
endef

ifdef SCENARIO_FILE
  export TOOLS_PERF_SCENARIO_FILE := $(SCENARIO_FILE)
endif

# -- Targets ----------------------------------------------------------------

help: ## Show this help
	@grep -E '^[a-z][a-z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk -F ':.*## ' '{printf "  %-26s %s\n", $$1, $$2}'

reports:
	@mkdir -p reports

# -- Full runs --------------------------------------------------------------

test: test-v3 ## Run all v3 tests (default)

test-v3: reports ## Run all v3 tests
	$(LOCUST) $(call BASE,v3-all)

test-v2: reports ## Run all v2 tests
	TOOLS_PERF_API_VERSION=v2 $(LOCUST) $(call BASE,v2-all)

test-all: reports ## Run v2 and v3 tests together
	TOOLS_PERF_API_VERSION=all $(LOCUST) $(call BASE,v2v3-all)

# -- Read-only runs (safe for prod / read replicas) -------------------------
# Explicitly list user classes that have readonly tasks to avoid Locust
# errors on classes that only have mutate tasks (e.g. SBOMLabelUserV3).

V3_READONLY := AdvisoryUserV3 AnalysisUserV3 GroupUserV3 ImporterUserV3 \
               LicenseUserV3 MiscUserV3 OrganizationUserV3 ProductUserV3 \
               PurlUserV3 SBOMUserV3 VulnerabilityUserV3 WeaknessUserV3 \
               AdvisoryLabelUserV3 WebsiteUser

test-readonly: reports ## Run only read-only v3 tests
	$(LOCUST) $(V3_READONLY) $(call BASE,v3-readonly) --tags readonly

test-readonly-v2: reports ## Run only read-only v2 tests
	TOOLS_PERF_API_VERSION=v2 $(LOCUST) RestAPIUserV2 AnalysisUserV2 WebsiteUser $(call BASE,v2-readonly) --tags readonly

test-readonly-all: reports ## Run only read-only v2+v3 tests
	TOOLS_PERF_API_VERSION=all $(LOCUST) $(V3_READONLY) RestAPIUserV2 AnalysisUserV2 $(call BASE,v2v3-readonly) --tags readonly

# -- Per-endpoint v3 runs ---------------------------------------------------

test-advisory: reports ## Run v3 advisory tests only
	$(LOCUST) AdvisoryUserV3 $(call BASE,v3-advisory)

test-vulnerability: reports ## Run v3 vulnerability tests only
	$(LOCUST) VulnerabilityUserV3 $(call BASE,v3-vulnerability)

test-sbom: reports ## Run v3 SBOM tests only
	$(LOCUST) SBOMUserV3 $(call BASE,v3-sbom)

test-purl: reports ## Run v3 pURL tests only
	$(LOCUST) PurlUserV3 $(call BASE,v3-purl)

test-product: reports ## Run v3 product tests only
	$(LOCUST) ProductUserV3 $(call BASE,v3-product)

test-organization: reports ## Run v3 organization tests only
	$(LOCUST) OrganizationUserV3 $(call BASE,v3-organization)

test-importer: reports ## Run v3 importer tests only
	$(LOCUST) ImporterUserV3 $(call BASE,v3-importer)

test-license: reports ## Run v3 license tests (incl. slow)
	$(LOCUST) LicenseUserV3 $(call BASE,v3-license)

test-weakness: reports ## Run v3 weakness tests only
	$(LOCUST) WeaknessUserV3 $(call BASE,v3-weakness)

test-group: reports ## Run v3 SBOM group tests only
	$(LOCUST) GroupUserV3 $(call BASE,v3-group)

test-misc: reports ## Run v3 misc tests only
	$(LOCUST) MiscUserV3 $(call BASE,v3-misc)

test-analysis-v3: reports ## Run v3 analysis tests only
	$(LOCUST) AnalysisUserV3 $(call BASE,v3-analysis)

test-analysis-v2: reports ## Run v2 analysis tests only
	TOOLS_PERF_API_VERSION=v2 $(LOCUST) AnalysisUserV2 $(call BASE,v2-analysis)

# -- Cross-cutting tag runs -------------------------------------------------

test-slow-v3: reports ## Run v3 slow queries only
	$(LOCUST) $(call BASE,v3-slow) --tags slow

test-labels-v3: reports ## Run v3 label mutation tests only
	$(LOCUST) AdvisoryLabelUserV3 SBOMLabelUserV3 $(call BASE,v3-labels)

# -- Utilities ---------------------------------------------------------------

test-website: reports ## Run website UI tests only
	$(LOCUST) WebsiteUser $(call BASE,website)

ui: ## Launch interactive web UI (no timeout)
	$(LOCUST) --host $(HOST)

# Default A/B to the two most recent _stats.csv files (latest-1 vs latest).
A ?= $(shell ls -t reports/*_stats.csv 2>/dev/null | sed -n '2p')
B ?= $(shell ls -t reports/*_stats.csv 2>/dev/null | sed -n '1p')

compare: ## Compare aggregates (default: latest-1 vs latest)
	@if [ -z "$(A)" ] || [ -z "$(B)" ]; then \
		echo "Need at least 2 reports in reports/. Run tests first."; exit 1; fi
	@echo "Baseline: $(A)"
	@echo "Current:  $(B)"
	@echo
	uv run python compare.py $(A) $(B)

compare-detail: ## Compare per-endpoint (default: latest-1 vs latest)
	@if [ -z "$(A)" ] || [ -z "$(B)" ]; then \
		echo "Need at least 2 reports in reports/. Run tests first."; exit 1; fi
	@echo "Baseline: $(A)"
	@echo "Current:  $(B)"
	@echo
	uv run python compare.py $(A) $(B) --detail

compare-csv: ## Compare as CSV (default: latest-1 vs latest)
	@if [ -z "$(A)" ] || [ -z "$(B)" ]; then \
		echo "Need at least 2 reports in reports/. Run tests first."; exit 1; fi
	uv run python compare.py $(A) $(B) --format csv

clean: ## Remove reports, CSV outputs, and cached files
	rm -rf reports/ results_*.csv
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
