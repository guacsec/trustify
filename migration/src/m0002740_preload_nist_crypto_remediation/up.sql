-- Initial seed only: the caller checks that the table is empty under an exclusive lock.
INSERT INTO crypto_remediation (
    id, algorithm_name, algorithm_primitive, replacement_name,
    replacement_standard, replacement_primitive
)
SELECT id, algorithm_name, algorithm_primitive, replacement_name,
       replacement_standard, replacement_primitive
FROM jsonb_to_recordset($1::jsonb) AS mapping(
    id uuid, algorithm_name text, algorithm_primitive text, replacement_name text,
    replacement_standard text, replacement_primitive text
);
