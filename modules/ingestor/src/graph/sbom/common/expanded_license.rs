use sea_orm::{ConnectionTrait, DbErr, Statement, TransactionTrait};
use uuid::Uuid;

/// Populates expanded_license and sbom_license_expanded tables during SBOM ingestion
///
/// This function uses two SQL statements within a transaction to:
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
/// **Transaction safety**: Both dictionary and junction table inserts run in a single
/// transaction to prevent partial state if the second insert fails.
///
/// **Note on SQL duplication**: Similar SQL appears in migration m0002120 for backfilling
/// existing data. The migration processes ALL SBOMs at once, while this function runs
/// per-SBOM during ingestion. Keep both in sync when updating license expansion logic.
pub async fn populate_expanded_license(
    sbom_id: Uuid,
    db: &(impl ConnectionTrait + TransactionTrait),
) -> Result<(), DbErr> {
    // Begin transaction to ensure atomicity between dictionary and junction table inserts
    let txn = db.begin().await?;

    // Step 1: Insert into expanded_license dictionary
    txn.execute(Statement::from_sql_and_values(
        txn.get_database_backend(),
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
    txn.execute(Statement::from_sql_and_values(
        txn.get_database_backend(),
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

    // Commit transaction - both inserts succeed or both roll back
    txn.commit().await?;

    Ok(())
}
