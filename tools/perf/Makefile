# Trustify Locust performance tests
#
# Usage:
#   make help                    Show available targets
#   make test                    Run all v3 tests (5m, 10 users)
#   make test-v2                 Run all v2 tests
#   make test-analysis-v2        Run v2 analysis tests only
#   make test HOST=my-host:8080  Override target host
#
# All TOOLS_PERF_* env vars are forwarded automatically.

.PHONY: help test test-v3 test-v2 test-all test-analysis-v3 test-analysis-v2 \
        test-rest-v3 test-rest-v2 test-slow-v3 test-slow-v2 test-labels-v3 \
        test-website ui clean

# -- Defaults (override on command line or via env) -------------------------

HOST          ?= http://localhost:8080
USERS         ?= 10
SPAWN_RATE    ?= 2
DURATION      ?= 5m
REPORT        ?= report.html
SCENARIO_FILE ?=

# -- Internal ---------------------------------------------------------------

LOCUST := uv run locust
BASE   := --host $(HOST) -u $(USERS) -r $(SPAWN_RATE) -t $(DURATION) \
          --headless --html=$(REPORT)

ifdef SCENARIO_FILE
  export TOOLS_PERF_SCENARIO_FILE := $(SCENARIO_FILE)
endif

# -- Targets ----------------------------------------------------------------

help: ## Show this help
	@grep -E '^[a-z][a-z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk -F ':.*## ' '{printf "  %-22s %s\n", $$1, $$2}'

test: test-v3 ## Run all v3 tests (default)

test-v3: ## Run all v3 tests
	$(LOCUST) $(BASE)

test-v2: ## Run all v2 tests
	TOOLS_PERF_API_VERSION=v2 $(LOCUST) $(BASE)

test-all: ## Run v2 and v3 tests together
	TOOLS_PERF_API_VERSION=all $(LOCUST) $(BASE)

test-rest-v3: ## Run v3 REST API tests only
	$(LOCUST) RestAPIUserV3 $(BASE)

test-rest-v2: ## Run v2 REST API tests only
	TOOLS_PERF_API_VERSION=v2 $(LOCUST) RestAPIUserV2 $(BASE)

test-analysis-v3: ## Run v3 analysis tests only
	$(LOCUST) AnalysisUserV3 $(BASE)

test-analysis-v2: ## Run v2 analysis tests only
	TOOLS_PERF_API_VERSION=v2 $(LOCUST) AnalysisUserV2 $(BASE)

test-slow-v3: ## Run v3 slow license queries only
	$(LOCUST) RestAPIUserSlowV3 $(BASE)

test-slow-v2: ## Run v2 slow license queries only
	TOOLS_PERF_API_VERSION=v2 $(LOCUST) RestAPIUserSlowV2 $(BASE)

test-labels-v3: ## Run v3 label mutation tests only
	$(LOCUST) AdvisoryLabelUserV3 SBOMLabelUserV3 $(BASE)

test-website: ## Run website UI tests only
	$(LOCUST) WebsiteUser $(BASE)

ui: ## Launch interactive web UI (no timeout)
	$(LOCUST) --host $(HOST)

clean: ## Remove reports, CSV outputs, and cached files
	rm -f report.html results_*.csv
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
