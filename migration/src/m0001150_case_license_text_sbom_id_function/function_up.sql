CREATE OR REPLACE FUNCTION case_license_text_sbom_id(
    license_text TEXT,
    sbom_id UUID
) RETURNS TEXT AS $$
BEGIN
RETURN CASE WHEN sbom_id IS NULL
        THEN license_text
        ELSE expand_license_expression(license_text, sbom_id)
    END CASE;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE;
