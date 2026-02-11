CREATE OR REPLACE FUNCTION expand_license_expression_with_mappings(
    license_text TEXT,
    license_mappings license_mapping[]
) RETURNS TEXT AS $$
DECLARE
    result_text TEXT := license_text;
    mapping license_mapping;
BEGIN
    IF license_text IS NULL
       OR POSITION('LicenseRef-' IN license_text) = 0
       OR license_mappings IS NULL
       OR array_length(license_mappings, 1) IS NULL THEN
        RETURN license_text;
    END IF;

    FOREACH mapping IN ARRAY license_mappings
    LOOP
        IF POSITION('LicenseRef-' IN result_text) = 0 THEN
            EXIT;
        END IF;
        result_text := regexp_replace(result_text, '\m' || mapping.license_id || '\M', mapping.name, 'g');
    END LOOP;

    RETURN result_text;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;
