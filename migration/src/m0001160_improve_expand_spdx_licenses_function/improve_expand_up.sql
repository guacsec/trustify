CREATE OR REPLACE FUNCTION expand_license_expression(
    license_text TEXT,
    sbom_id_param UUID
) RETURNS TEXT AS $$
DECLARE
    result_text TEXT := license_text;
    license_mapping RECORD;
BEGIN
    -- Replace each license reference with its corresponding name
    FOR license_mapping IN
        SELECT license_id, name
        FROM licensing_infos
        WHERE sbom_id = sbom_id_param
    LOOP
        -- Exit early if no more LicenseRef- patterns exist in the text
        IF result_text !~ 'LicenseRef-' THEN
            EXIT;
        END IF;
        -- Replace the license_id with the license name in the expression
        -- This handles exact matches and license references within expressions
        result_text := regexp_replace(result_text, '\m' || license_mapping.license_id || '\M', license_mapping.name, 'g');
END LOOP;

RETURN result_text;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE;
