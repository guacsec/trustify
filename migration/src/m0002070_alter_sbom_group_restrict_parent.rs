use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn apply_fkey(manager: &SchemaManager<'_>, action: ForeignKeyAction) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(SbomGroup::Table)
                .drop_foreign_key("sbom_group_parent_fkey")
                .to_owned(),
        )
        .await?;

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
                        .on_delete(action),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        apply_fkey(manager, ForeignKeyAction::Restrict).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        apply_fkey(manager, ForeignKeyAction::Cascade).await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SbomGroup {
    Table,
    Id,
    Parent,
}
