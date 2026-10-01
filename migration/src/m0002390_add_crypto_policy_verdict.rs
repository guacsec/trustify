use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomCrypto::Table)
                    .add_column(ColumnDef::new(SbomCrypto::PolicyVerdict).string().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomCrypto::Table)
                    .drop_column(SbomCrypto::PolicyVerdict)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum SbomCrypto {
    Table,
    PolicyVerdict,
}
