-- Undo the initial seed without deleting mappings whose guidance has been customized.
DELETE FROM crypto_remediation stored
USING jsonb_to_recordset($1::jsonb) AS seed(
    algorithm_name text, algorithm_primitive text, replacement_name text,
    replacement_standard text, replacement_primitive text
)
WHERE stored.algorithm_name = seed.algorithm_name
  AND stored.algorithm_primitive IS NOT DISTINCT FROM seed.algorithm_primitive
  AND stored.replacement_name = seed.replacement_name
  AND stored.replacement_standard IS NOT DISTINCT FROM seed.replacement_standard
  AND stored.replacement_primitive IS NOT DISTINCT FROM seed.replacement_primitive;
