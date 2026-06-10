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
                    .table(SbomExternalNode::Table)
                    .name(Indexes::IdxSbomExternalNodeRef.to_string())
                    .col(SbomExternalNode::SbomId)
                    .col(SbomExternalNode::ExternalNodeRef)
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
                    .table(SbomExternalNode::Table)
                    .name(Indexes::IdxSbomExternalNodeRef.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Indexes {
    IdxSbomExternalNodeRef,
}

#[derive(DeriveIden)]
enum SbomExternalNode {
    Table,
    SbomId,
    ExternalNodeRef,
}
