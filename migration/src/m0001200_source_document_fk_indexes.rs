use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create index on advisory.source_document_id
        // This FK was missing an index, causing severe performance issues
        // when deleting source_documents (must scan 596K+ advisory rows)
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisorySourceDocumentIdIdx.to_string())
                    .col(Advisory::SourceDocumentId)
                    .to_owned(),
            )
            .await?;

        // Create index on sbom.source_document_id
        // This FK was also missing an index, causing performance issues
        // during source_document deletion and SBOM lookups
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(Sbom::Table)
                    .name(Indexes::SbomSourceDocumentIdIdx.to_string())
                    .col(Sbom::SourceDocumentId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop index on sbom.source_document_id
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Sbom::Table)
                    .name(Indexes::SbomSourceDocumentIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        // Drop index on advisory.source_document_id
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisorySourceDocumentIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    AdvisorySourceDocumentIdIdx,
    SbomSourceDocumentIdIdx,
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    SourceDocumentId,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    SourceDocumentId,
}
