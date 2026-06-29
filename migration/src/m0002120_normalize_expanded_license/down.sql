-- Drop new tables
DROP TABLE IF EXISTS sbom_license_expanded;
DROP TABLE IF EXISTS expanded_license;

-- Restore expand_license_expression_with_mappings to the m0002110 regex-based version
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
        result_text := regexp_replace(result_text, '\m' || mapping.license_id || '(?![a-zA-Z0-9.\-])', mapping.name, 'g');
    END LOOP;

    RETURN result_text;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;

-- Restore old functions for backward compatibility

-- expand_license_expression (from m0001160)
CREATE OR REPLACE FUNCTION expand_license_expression(
    license_text TEXT,
    sbom_id_param UUID
) RETURNS TEXT AS $$
DECLARE
    result_text TEXT := license_text;
    license_mapping RECORD;
BEGIN
    FOR license_mapping IN
        SELECT license_id, name
        FROM licensing_infos
        WHERE sbom_id = sbom_id_param
    LOOP
        IF result_text !~ 'LicenseRef-' THEN
            EXIT;
        END IF;
        result_text := regexp_replace(result_text, '\m' || license_mapping.license_id || '\M', license_mapping.name, 'g');
    END LOOP;
    RETURN result_text;
END;
$$ LANGUAGE plpgsql STABLE;

-- case_license_text_sbom_id (from m0001150)
CREATE OR REPLACE FUNCTION case_license_text_sbom_id(
    license_text TEXT,
    sbom_id_param UUID
) RETURNS TEXT AS $$
BEGIN
    RETURN expand_license_expression(license_text, sbom_id_param);
END;
$$ LANGUAGE plpgsql STABLE;
