use sea_orm::{ConnectionTrait, DbErr, Statement};
use uuid::Uuid;

/// Populates expanded_license and sbom_license_expanded tables during SBOM ingestion
///
/// This function uses raw SQL because the query involves:
/// - PostgreSQL composite type `license_mapping` constructed with `ROW(...)`
/// - Array aggregation `array_agg()` over composite types
/// - Custom PL/pgSQL function `expand_license_expression_with_mappings()`
/// - Complex CTEs and subquery joins
///
/// While SeaORM could express this via custom expressions, it would be significantly
/// more verbose and harder to maintain than the raw SQL.
pub async fn populate_expanded_license(
    sbom_id: Uuid,
    db: &impl ConnectionTrait,
) -> Result<(), DbErr> {
    // Step 1: Insert into expanded_license dictionary
    db.execute(Statement::from_sql_and_values(
        db.get_database_backend(),
        r#"
INSERT INTO expanded_license (expanded_text)
SELECT DISTINCT expand_license_expression_with_mappings(
    l.text,
    COALESCE(lim.license_mapping, ARRAY[]::license_mapping[])
)
FROM sbom_package_license spl
JOIN license l ON l.id = spl.license_id
LEFT JOIN (
    SELECT array_agg(ROW(license_id, name)::license_mapping) AS license_mapping, sbom_id
    FROM licensing_infos
    GROUP BY sbom_id
) lim ON lim.sbom_id = spl.sbom_id
WHERE spl.sbom_id = $1
ON CONFLICT (text_hash) DO NOTHING
            "#,
        [sbom_id.into()],
    ))
    .await?;

    // Step 2: Insert into sbom_license_expanded junction table
    // Use CTE to call expand_license_expression_with_mappings() only once per (sbom_id, license_id)
    db.execute(Statement::from_sql_and_values(
        db.get_database_backend(),
        r#"
WITH license_expansions AS (
    SELECT DISTINCT
        spl.sbom_id,
        spl.license_id,
        expand_license_expression_with_mappings(
            l.text,
            COALESCE(lim.license_mapping, ARRAY[]::license_mapping[])
        ) AS expanded_text
    FROM sbom_package_license spl
    JOIN license l ON l.id = spl.license_id
    LEFT JOIN (
        SELECT array_agg(ROW(license_id, name)::license_mapping) AS license_mapping, sbom_id
        FROM licensing_infos
        GROUP BY sbom_id
    ) lim ON lim.sbom_id = spl.sbom_id
    WHERE spl.sbom_id = $1
)
INSERT INTO sbom_license_expanded (sbom_id, license_id, expanded_license_id)
SELECT le.sbom_id, le.license_id, el.id
FROM license_expansions le
JOIN expanded_license el ON el.text_hash = md5(le.expanded_text)
ON CONFLICT (sbom_id, license_id) DO UPDATE
SET expanded_license_id = EXCLUDED.expanded_license_id
            "#,
        [sbom_id.into()],
    ))
    .await?;

    Ok(())
}
