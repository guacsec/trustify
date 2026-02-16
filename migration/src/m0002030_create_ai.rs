use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SbomAi::Table)
                    .col(ColumnDef::new(SbomAi::SbomId).uuid().not_null())
                    .col(ColumnDef::new(SbomAi::NodeId).string().not_null())
                    .col(
                        ColumnDef::new(SbomAi::Properties)
                            .json_binary()
                            .not_null()
                            .default(serde_json::Value::Null),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomAi::SbomId)
                            .col(SbomAi::NodeId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(SbomAi::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SbomAi::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SbomAi {
    Table,
    SbomId,
    NodeId,
    Properties,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    SbomId,
}
