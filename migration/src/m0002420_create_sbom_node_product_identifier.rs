use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TABLE correlation_evidence DROP COLUMN IF EXISTS match_dimension;
DROP TYPE IF EXISTS match_dimension;

CREATE TABLE IF NOT EXISTS sbom_node_product_identifier (
    sbom_id          UUID NOT NULL REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    node_id          TEXT NOT NULL,
    identifier_type  product_identifier_type NOT NULL,
    value            TEXT NOT NULL,
    PRIMARY KEY (sbom_id, node_id, identifier_type, value)
);

CREATE INDEX IF NOT EXISTS idx_sbom_node_product_id_value
    ON sbom_node_product_identifier (value);

CREATE INDEX IF NOT EXISTS idx_sbom_node_product_id_type_value
    ON sbom_node_product_identifier (identifier_type, value);
"#,
            )
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
DROP TABLE IF EXISTS sbom_node_product_identifier;

CREATE TYPE match_dimension AS ENUM ('digest', 'purl', 'cpe');
ALTER TABLE correlation_evidence
    ADD COLUMN match_dimension match_dimension NOT NULL DEFAULT 'digest';
"#,
            )
            .await
            .map(|_| ())
    }
}
