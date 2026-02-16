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
                    .add_column_if_not_exists(ColumnDef::new(SbomGroup::Description).null().text())
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"
CREATE INDEX IF NOT EXISTS sbom_group_description ON {}
USING GIN ({} gin_trgm_ops)
"#,
                SbomGroup::Table.to_string(),
                SbomGroup::Description.to_string()
            ))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomGroup::Table)
                    .drop_column(SbomGroup::Description)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SbomGroup {
    Table,
    Description,
}
