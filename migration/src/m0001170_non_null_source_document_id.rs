use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .modify_column(ColumnDef::new(Advisory::SourceDocumentId).not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(ColumnDef::new(Sbom::SourceDocumentId).not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(ColumnDef::new(Sbom::SourceDocumentId).null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .modify_column(ColumnDef::new(Advisory::SourceDocumentId).null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
enum Advisory {
    Table,
    SourceDocumentId,
}

#[derive(Iden)]
enum Sbom {
    Table,
    SourceDocumentId,
}
