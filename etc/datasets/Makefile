.PHONY: all
all: ds1.zip ds3.zip

.PHONY: ds1.zip
ds1.zip:
	-rm ds1.zip
	cd ds1 && zip -r ../ds1.zip .

.PHONY: ds3.zip
ds3.zip:
	-rm ds3.zip
	cd ds3 && zip -r ../ds3.zip .

.PHONY: ds3-sboms.zip
ds3-sboms.zip:
	-rm ds3-sbom.zip
	cd ds3 && zip -r ../ds3-sboms.zip ./spdx

TRUSTIFY_UI_REPO ?= https://github.com/trustification/trustify-ui.git
TRUSTIFY_UI_BRANCH ?= main

.PHONY: ds6
ds6:
	rm -rf ds6 ds6-tmp
	git clone --depth 1 --branch $(TRUSTIFY_UI_BRANCH) --filter=blob:none --sparse $(TRUSTIFY_UI_REPO) ds6-tmp
	cd ds6-tmp && git sparse-checkout set e2e/tests/common/dataset
	mv ds6-tmp/e2e/tests/common/dataset ds6
	rm -rf ds6-tmp
