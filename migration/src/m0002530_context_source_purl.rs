use sea_orm_migration::prelude::*;

/// Contexts derived from an RPM's PURL: its `distro=` qualifier, or its release.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TYPE correlation_context_source ADD VALUE IF NOT EXISTS 'purl_qualifier';
ALTER TYPE correlation_context_source ADD VALUE IF NOT EXISTS 'purl_release';
"#,
            )
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // values can't be removed from an enum: recreate it without them
        manager
            .get_connection()
            .execute_unprepared(
                r#"
DELETE FROM correlation_evidence_context
    WHERE source::text IN ('purl_qualifier', 'purl_release');
ALTER TYPE correlation_context_source RENAME TO correlation_context_source_old;
CREATE TYPE correlation_context_source AS ENUM (
    'node', 'ancestor_node', 'describing', 'ancestor_sbom'
);
ALTER TABLE correlation_evidence_context
    ALTER COLUMN source TYPE correlation_context_source
    USING source::text::correlation_context_source;
DROP TYPE correlation_context_source_old;
"#,
            )
            .await
            .map(|_| ())
    }
}
