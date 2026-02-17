use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomGroup::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .from_tbl(SbomGroup::Table)
                            .from_col(SbomGroup::Parent)
                            .to_tbl(SbomGroup::Table)
                            .to_col(SbomGroup::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomGroup::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .from_tbl(SbomGroup::Table)
                            .from_col(SbomGroup::Parent)
                            .to_tbl(SbomGroup::Table)
                            .to_col(SbomGroup::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SbomGroup {
    Table,
    Id,
    Parent,
}
