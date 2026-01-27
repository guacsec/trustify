use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SbomGroup::Table)
                    .col(
                        ColumnDef::new(SbomGroup::Id)
                            .uuid()
                            .not_null()
                            .primary_key()
                            .to_owned(),
                    )
                    .col(ColumnDef::new(SbomGroup::Parent).uuid().to_owned())
                    .col(
                        ColumnDef::new(SbomGroup::Name)
                            .string()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(SbomGroup::Revision)
                            .uuid()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(SbomGroup::Labels)
                            .json_binary()
                            .not_null()
                            .to_owned(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SbomGroup::Table, SbomGroup::Parent)
                            .to(SbomGroup::Table, SbomGroup::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomGroup::Table)
                    .col(SbomGroup::Parent)
                    .col(SbomGroup::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomGroup::Table)
                    .col(SbomGroup::Parent)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomGroup::Table)
                    .col(SbomGroup::Labels)
                    .index_type(IndexType::Custom(Alias::new("GIN").into_iden()))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SbomGroupAssignment::Table)
                    .col(
                        ColumnDef::new(SbomGroupAssignment::SbomId)
                            .uuid()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(SbomGroupAssignment::GroupId)
                            .uuid()
                            .not_null()
                            .to_owned(),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomGroupAssignment::SbomId)
                            .col(SbomGroupAssignment::GroupId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(SbomGroupAssignment::GroupId)
                            .to(SbomGroup::Table, SbomGroup::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(SbomGroupAssignment::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomGroupAssignment::Table)
                    .col(SbomGroupAssignment::SbomId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomGroupAssignment::Table)
                    .col(SbomGroupAssignment::GroupId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SbomGroupAssignment::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(SbomGroup::Table).if_exists().to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    SbomId,
}

#[derive(DeriveIden)]
enum SbomGroup {
    Table,
    Id,
    Parent,
    Name,
    Revision,
    Labels,
}

#[derive(DeriveIden)]
enum SbomGroupAssignment {
    Table,
    SbomId,
    GroupId,
}
