use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop GiST trigram indexes on qualified_purl that were
        // accidentally reintroduced by the migration squash (a53ef329).
        // These were intentionally removed in cab2b594 because the
        // codebase only uses ILIKE queries, which are served by the
        // existing GIN trigram indexes on the same columns. The GiST
        // indexes cause the planner to pick a slower scan path.
        for idx in GIST_INDEXES {
            manager
                .drop_index(
                    Index::drop()
                        .if_exists()
                        .name(*idx)
                        .table(QualifiedPurl::Table)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (idx, expr) in GIST_INDEXES.iter().zip(GIST_EXPRS.iter()) {
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    r#"CREATE INDEX IF NOT EXISTS {idx}
                       ON qualified_purl
                       USING GIST (({expr}) gist_trgm_ops)"#,
                ))
                .await
                .map(|_| ())?;
        }

        Ok(())
    }
}

const GIST_INDEXES: &[&str] = &[
    "qualifiedpurlnamejsongistidx",
    "qualifiedpurlnamespacejsongistidx",
    "qualifiedpurltypejsongistidx",
    "qualifiedpurlversionjsongistidx",
];

const GIST_EXPRS: &[&str] = &[
    "purl ->> 'name'",
    "purl ->> 'namespace'",
    "purl ->> 'ty'",
    "purl ->> 'version'",
];

#[derive(DeriveIden)]
pub enum QualifiedPurl {
    Table,
}
