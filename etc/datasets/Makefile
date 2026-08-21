.PHONY: all
all: ds1.zip ds3.zip sales-demo.zip sales-demo-mini.zip

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

.PHONY: sales-demo.zip
sales-demo.zip:
	-rm sales-demo.zip
	cd sales-demo && zip -r ../sales-demo.zip . -x '*.DS_Store' -x 'download.sh' -x 'fetch-vulns.sh' -x 'sbom-list.txt'

.PHONY: sales-demo-mini.zip
sales-demo-mini.zip:
	-rm sales-demo-mini.zip
	cd sales-demo-mini && zip -r ../sales-demo-mini.zip . -x '*.DS_Store'

TRUSTIFY_UI_REPO ?= https://github.com/trustification/trustify-ui.git
TRUSTIFY_UI_BRANCH ?= main

.PHONY: ds6
ds6:
	rm -rf ds6 ds6-tmp
	git clone --depth 1 --branch $(TRUSTIFY_UI_BRANCH) --filter=blob:none --sparse $(TRUSTIFY_UI_REPO) ds6-tmp
	cd ds6-tmp && git sparse-checkout set e2e/tests/common/dataset
	mv ds6-tmp/e2e/tests/common/dataset ds6
	rm -rf ds6-tmp
