use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement};
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
    /// Uses SQL file to leverage expand_license_expression_with_mappings() PL/pgSQL function
    /// which cannot be called via SeaORM due to custom composite type parameters.
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        // Execute SQL with sbom_id parameter binding
        db.execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            include_str!("expanded_license_insert.sql"),
            [self.sbom_id.into()],
        ))
        .await?;

        Ok(())
    }
}
