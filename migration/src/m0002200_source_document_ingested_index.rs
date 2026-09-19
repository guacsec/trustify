use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Index on source_document(ingested DESC) to speed up advisory listing
        // sorted by ingestion date. Without this, the query must scan and sort
        // ~1M rows just to return the first page.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(SourceDocument::Table)
                    .name(Indexes::IdxSourceDocumentIngested.to_string())
                    .col((SourceDocument::Ingested, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SourceDocument::Table)
                    .name(Indexes::IdxSourceDocumentIngested.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Indexes {
    IdxSourceDocumentIngested,
}

#[derive(DeriveIden)]
enum SourceDocument {
    Table,
    Ingested,
}
