# Trustify Locust performance tests
#
# Usage:
#   make help                    Show available targets
#   make test                    Run the daily dashboard endpoint set
#   make test-v3                 Run all v3 endpoint groups
#   make test-readonly           Run only read-only v3 tests
#   make test HOST=my-host:8080  Override target host
#   make report                  Regenerate the custom dashboard from saved CSVs
#
# Custom HTML output is written to reports/dashboard/index.html.
#
# All TOOLS_PERF_* env vars are forwarded automatically.

.PHONY: help reports report test test-daily test-v3 test-all test-readonly \
        test-slow test-website ui compare compare-detail compare-csv clean

# -- Defaults (override on command line or via env) -------------------------

HOST          ?= http://localhost:8080
USERS         ?= 10
SPAWN_RATE    ?= 2
DURATION      ?= 5m
SCENARIO_FILE ?=
ifeq ($(strip $(SCENARIO_FILE)),)
SCENARIO_FILE := $(if $(TOOLS_PERF_SCENARIO_FILE),$(TOOLS_PERF_SCENARIO_FILE),etc/scenarios/main/full-20260317T023702Z.json5)
endif
REPORT_DIR     ?= reports/dashboard
REPORT_TITLE   ?= Trustify Locust performance tests
REPORT_TARGET  ?= $(HOST)

# -- Internal ---------------------------------------------------------------

LOCUST    := uv run locust
TIMESTAMP := $(shell date +%Y%m%dT%H%M%S)

# run_prefix(target) -- generates the base path for report outputs:
#   reports/v3-readonly_u10_5m_20260729T143022
# Locust appends _stats.csv / _stats_history.csv / _failures.csv /
# _exceptions.csv for --csv. The custom reporter builds HTML from these CSVs.
run_prefix = reports/$(1)_u$(USERS)_$(DURATION)_$(TIMESTAMP)

# BASE is constructed per-target using $(call run_prefix,<target>)
define BASE
--host $(HOST) -u $(USERS) -r $(SPAWN_RATE) -t $(DURATION) \
--headless --csv-full-history --csv=$(call run_prefix,$(1))
endef

REPORT_CMD = uv run python locust_report.py index reports -o "$(REPORT_DIR)" --prune \
            --title "$(REPORT_TITLE)" --target "$(REPORT_TARGET)"

define RUN_AND_REPORT
interrupted=0; locust_status=0; \
trap 'interrupted=1' INT TERM; \
$(LOCUST) $(1) || locust_status=$$?; \
trap - INT TERM; \
$(REPORT_CMD); report_status=$$?; \
if [ "$$interrupted" -ne 0 ]; then exit 130; fi; \
if [ "$$locust_status" -ne 0 ]; then exit "$$locust_status"; fi; \
exit "$$report_status"
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

report: reports ## Generate the custom HTML dashboard from saved Locust CSVs
	$(REPORT_CMD)

# -- Full runs --------------------------------------------------------------

V3_DAILY_USERS := AdvisoryUserV3 AnalysisUserV3 GroupUserV3 ImporterUserV3 \
                  AdvisoryLabelUserV3 LicenseUserV3 PurlUserV3 \
                  SBOMUserV3 VulnerabilityUserV3

test: test-daily ## Run the endpoint groups shown in the daily dashboard (default)

test-daily: reports ## Run the daily dashboard v3 endpoint groups
	@$(call RUN_AND_REPORT,$(V3_DAILY_USERS) $(call BASE,daily))

test-v3: reports ## Run all v3 tests
	@$(call RUN_AND_REPORT,$(call BASE,v3-all))

test-all: reports ## Run v2 and v3 tests together
	@TOOLS_PERF_API_VERSION=all $(call RUN_AND_REPORT,$(call BASE,v2v3-all))

# -- Read-only runs (safe for prod / read replicas) -------------------------
# Explicitly list user classes that have readonly tasks to avoid Locust
# errors on classes that only have mutate tasks (e.g. SBOMLabelUserV3).

V3_READONLY := AdvisoryUserV3 AnalysisUserV3 GroupUserV3 ImporterUserV3 \
               LicenseUserV3 MiscUserV3 OrganizationUserV3 ProductUserV3 \
               PurlUserV3 SBOMUserV3 VulnerabilityUserV3 WeaknessUserV3 \
               AdvisoryLabelUserV3 WebsiteUser

test-readonly: reports ## Run only read-only v3 tests
	@$(call RUN_AND_REPORT,$(V3_READONLY) $(call BASE,v3-readonly) --tags readonly)


# -- Cross-cutting tag runs -------------------------------------------------

test-slow: reports ## Run v3 slow queries only
	@$(call RUN_AND_REPORT,$(call BASE,v3-slow) --tags slow)

# -- Utilities ---------------------------------------------------------------

test-website: reports ## Run website UI tests only
	@$(call RUN_AND_REPORT,WebsiteUser $(call BASE,website))

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
