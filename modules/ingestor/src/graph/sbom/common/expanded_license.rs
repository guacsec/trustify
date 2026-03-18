use sea_orm::{ConnectionTrait, DbErr, Statement};
use uuid::Uuid;

/// Populates expanded_license and sbom_license_expanded tables during SBOM ingestion
///
/// This function uses a single SQL statement with CTEs to:
/// 1. Call expand_license_expression_with_mappings() once per license
/// 2. Insert distinct expanded texts into the expanded_license dictionary
/// 3. Populate the sbom_license_expanded junction table
///
/// Raw SQL is used because the query involves:
/// - PostgreSQL composite type `license_mapping` constructed with `ROW(...)`
/// - Array aggregation `array_agg()` over composite types
/// - Custom PL/pgSQL function `expand_license_expression_with_mappings()`
/// - Complex CTEs with multiple insert operations
///
/// While SeaORM could express this via custom expressions, it would be significantly
/// more verbose and harder to maintain than the raw SQL.
///
/// # Differences from Migration Backfill
///
/// The migration in m0002120_normalize_expanded_license/up.sql performs a similar
/// operation but with key differences:
/// - Migration: Pre-deduplicates by (text, sbom_id) and uses WHERE NOT EXISTS to skip
///   already-backfilled SBOMs. Optimized for one-time bulk processing.
/// - Ingestion: Filters by specific sbom_id parameter for single-SBOM processing.
///   Uses ON CONFLICT for idempotent re-ingestion of the same SBOM.
///
/// Both use the same core logic (expand_license_expression_with_mappings + md5 hash
/// matching) but optimize for their different use cases.
pub async fn populate_expanded_license<C>(sbom_id: Uuid, db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
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
