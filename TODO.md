# TODO

- [ ] The CSAF crate expects `file_name` but the CSAF 2.0 spec uses `filename` in
  `product_identification_helper.hashes[].file_name`. The test advisory
  (`vex/vde-2025-106.json`) has been patched to use `file_name`. Once the upstream
  `csaf` crate is fixed to accept `filename`, revert this rename and use the
  original document as-is.
- [ ] Correlation: product scope for assertions. Adopt the CSAF vendor → product → version
  hierarchy (and `relationships`, e.g. `default_component_of`) as the context of a vulnerability
  assertion, to filter or down-rank assertions which don't match an SBOM's context. Open points:
  the SBOM side needs a context too (e.g. the described root component), products should be
  identified by CPE/PURL rather than by free text names, non-CSAF sources (OSV, CVE) express scope
  differently, and it should probably start as a confidence modifier rather than a filter.
- [ ] CSAF ingestion ignores products not defined as branch leaves
  ([#2740](https://github.com/guacsec/trustify/issues/2740)). CSAF 2.0 (mandatory test 6.1.2)
  defines product IDs in three places: `product_tree.branches[]…product`,
  `product_tree.full_product_names[]` and `product_tree.relationships[].full_product_name`.
  `ResolveProductIdCache` only indexes branches, so products from the other two get no
  `purl_status`, no remediation links, and no advisory side correlation data (hashes, product
  identifiers, CPEs).
