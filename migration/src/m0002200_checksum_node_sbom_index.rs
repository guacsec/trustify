use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(SbomNodeChecksum::Table)
                    .name(Indexes::SbomNodeChecksumNodeSbomIdx.to_string())
                    .col(SbomNodeChecksum::NodeId)
                    .col(SbomNodeChecksum::SbomId)
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
                    .table(SbomNodeChecksum::Table)
                    .name(Indexes::SbomNodeChecksumNodeSbomIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Indexes {
    SbomNodeChecksumNodeSbomIdx,
}

#[derive(DeriveIden)]
enum SbomNodeChecksum {
    Table,
    NodeId,
    SbomId,
}
