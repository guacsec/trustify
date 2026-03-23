use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Sbom::Table)
                    .name("advisory_labels_idx")
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(Advisory::Table)
                    .name("advisory_labels_idx")
                    .col(Advisory::Labels)
                    .index_type(IndexType::Custom(Alias::new("GIN").into_iden()))
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
                    .table(Advisory::Table)
                    .name("advisory_labels_idx")
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(Sbom::Table)
                    .name("advisory_labels_idx")
                    .col(Sbom::Labels)
                    .index_type(IndexType::Custom(Alias::new("GIN").into_iden()))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Advisory {
    Table,
    Labels,
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    Labels,
}
