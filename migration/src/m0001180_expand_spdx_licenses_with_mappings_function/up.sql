-- Performance optimization for license expansion functions
-- This migration replaces the functions to accept license mappings as arrays
-- instead of querying the database per row, significantly improving performance

-- Create a composite type to hold license mappings
CREATE TYPE license_mapping AS (
    license_id TEXT,
    name TEXT
);

CREATE OR REPLACE FUNCTION expand_license_expression_with_mappings(
    license_text TEXT,
    license_mappings license_mapping[]
) RETURNS TEXT AS $$
DECLARE
    result_text TEXT := license_text;
    mapping license_mapping;
BEGIN
    -- Return early if no mappings provided or license_text is NULL
    IF license_mappings IS NULL OR array_length(license_mappings, 1) IS NULL OR license_text IS NULL THEN
        RETURN license_text;
    END IF;

    -- Replace each license reference with its corresponding name
    FOREACH mapping IN ARRAY license_mappings
    LOOP
        -- Exit early if no more LicenseRef- patterns exist in the text
        IF result_text !~ 'LicenseRef-' THEN
            EXIT;
        END IF;

        -- Replace the license_id with the license name in the expression
        -- This handles exact matches and license references within expressions
        -- \m and \M are word boundary anchors to match whole words only
        result_text := regexp_replace(result_text, '\m' || mapping.license_id || '\M', mapping.name, 'g');
    END LOOP;

    RETURN result_text;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;
