use sea_orm_migration::prelude::*;
use sea_query::extension::postgres::Type;
use strum::VariantNames;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_connection().get_database_backend();

        // The `Table` variant of each enum names the PostgreSQL type, so it is
        // skipped when emitting the value list.
        for stmt in [
            Type::create()
                .as_enum(ValidationMode::Table)
                .values(ValidationMode::VARIANTS.iter().skip(1).copied())
                .to_owned(),
            Type::create()
                .as_enum(ValidationOutcome::Table)
                .values(ValidationOutcome::VARIANTS.iter().skip(1).copied())
                .to_owned(),
            Type::create()
                .as_enum(ValidationSeverity::Table)
                .values(ValidationSeverity::VARIANTS.iter().skip(1).copied())
                .to_owned(),
            Type::create()
                .as_enum(ValidationIngestSource::Table)
                .values(ValidationIngestSource::VARIANTS.iter().skip(1).copied())
                .to_owned(),
        ] {
            manager
                .get_connection()
                .execute_unprepared(&builder.build(&stmt).to_string())
                .await?;
        }

        manager
            .create_table(
                Table::create()
                    .table(ValidationReport::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ValidationReport::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::DocumentSha256)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::Validator)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::Mode)
                            .custom(ValidationMode::Table)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::Outcome)
                            .custom(ValidationOutcome::Table)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::Blocked)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::MaxSeverity)
                            .custom(ValidationSeverity::Table)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::FindingCount)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::Findings)
                            .json_binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::Truncated)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::ContentHash)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::ConfigFingerprint)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ValidationReport::IngestSource)
                            .custom(ValidationIngestSource::Table)
                            .not_null(),
                    )
                    .col(ColumnDef::new(ValidationReport::ImporterName).text().null())
                    .col(
                        ColumnDef::new(ValidationReport::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Rows are append-only: a validation run inserts only when its result
        // differs from the latest stored one. Reads resolve the current result
        // with `DISTINCT ON (document_sha256, validator) ORDER BY created_at
        // DESC`, which this index serves; its leading column also serves
        // lookups by digest alone. Deliberately no index on `created_at`: the
        // table is write-heavy and read paths are nearly always filtered by
        // document or by `blocked`.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX IF NOT EXISTS idx_validation_report_document_validator
                    ON validation_report (document_sha256, validator, created_at DESC)
                "#,
            )
            .await?;

        // Rejections are rare, so a partial index stays small and costs a write
        // only for the rows it covers. It backs "what did this instance refuse",
        // which has no document to filter on.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX IF NOT EXISTS idx_validation_report_blocked
                    ON validation_report (created_at DESC) WHERE blocked
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ValidationReport::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        for name in [
            ValidationIngestSource::Table.into_iden(),
            ValidationSeverity::Table.into_iden(),
            ValidationOutcome::Table.into_iden(),
            ValidationMode::Table.into_iden(),
        ] {
            manager
                .drop_type(Type::drop().if_exists().name(name).to_owned())
                .await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum ValidationReport {
    Table,
    Id,
    DocumentSha256,
    Validator,
    Mode,
    Outcome,
    Blocked,
    MaxSeverity,
    FindingCount,
    Findings,
    Truncated,
    ContentHash,
    ConfigFingerprint,
    IngestSource,
    ImporterName,
    CreatedAt,
}

#[derive(DeriveIden, strum::VariantNames)]
#[strum(serialize_all = "lowercase")]
#[allow(unused)]
pub enum ValidationMode {
    Table,
    Report,
    Verify,
}

#[derive(DeriveIden, strum::VariantNames)]
#[strum(serialize_all = "lowercase")]
#[allow(unused)]
pub enum ValidationOutcome {
    Table,
    Passed,
    Failed,
}

#[derive(DeriveIden, strum::VariantNames)]
#[strum(serialize_all = "lowercase")]
#[allow(unused)]
pub enum ValidationSeverity {
    Table,
    Info,
    Warning,
    Error,
    Fatal,
}

#[derive(DeriveIden, strum::VariantNames)]
#[strum(serialize_all = "lowercase")]
#[allow(unused)]
pub enum ValidationIngestSource {
    Table,
    Api,
    Importer,
    Dataset,
    Internal,
}
