use sea_orm::{ConnectionTrait, DbErr, Statement};
use uuid::Uuid;

/// Creator for populating expanded_license and sbom_license_expanded tables during ingestion
pub struct ExpandedLicenseCreator {
    sbom_id: Uuid,
}

impl ExpandedLicenseCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self { sbom_id }
    }

    /// Populates expanded_license and sbom_license_expanded tables
    ///
    /// Uses inline SQL to leverage expand_license_expression_with_mappings() PL/pgSQL function
    /// which cannot be called via SeaORM due to custom composite type parameters.
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
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
ON CONFLICT (md5(expanded_text)) DO NOTHING
            "#,
            [self.sbom_id.into()],
        ))
        .await?;

        // Step 2: Insert into sbom_license_expanded junction table
        db.execute(Statement::from_sql_and_values(
            db.get_database_backend(),
            r#"
INSERT INTO sbom_license_expanded (sbom_id, license_id, expanded_license_id)
SELECT DISTINCT spl.sbom_id, spl.license_id, el.id
FROM sbom_package_license spl
JOIN license l ON l.id = spl.license_id
LEFT JOIN (
    SELECT array_agg(ROW(license_id, name)::license_mapping) AS license_mapping, sbom_id
    FROM licensing_infos
    GROUP BY sbom_id
) lim ON lim.sbom_id = spl.sbom_id
JOIN expanded_license el ON md5(el.expanded_text) = md5(
    expand_license_expression_with_mappings(
        l.text,
        COALESCE(lim.license_mapping, ARRAY[]::license_mapping[])
    )
)
WHERE spl.sbom_id = $1
ON CONFLICT (sbom_id, license_id) DO UPDATE
SET expanded_license_id = EXCLUDED.expanded_license_id
            "#,
            [self.sbom_id.into()],
        ))
        .await?;

        Ok(())
    }
}
