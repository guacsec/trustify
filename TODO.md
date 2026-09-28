# TODO

- [ ] The CSAF crate expects `file_name` but the CSAF 2.0 spec uses `filename` in
  `product_identification_helper.hashes[].file_name`. The test advisory
  (`vex/vde-2025-106.json`) has been patched to use `file_name`. Once the upstream
  `csaf` crate is fixed to accept `filename`, revert this rename and use the
  original document as-is.
