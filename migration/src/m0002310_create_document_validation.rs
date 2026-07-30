use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DocumentValidation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DocumentValidation::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(DocumentValidation::EntityType)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DocumentValidation::EntityId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DocumentValidation::Level)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DocumentValidation::Message)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DocumentValidation::Source)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DocumentValidation::Key)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DocumentValidation::Timestamp)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(DocumentValidation::Table)
                    .name(Indexes::UqDocumentValidationSourceKey.to_string())
                    .col(DocumentValidation::EntityType)
                    .col(DocumentValidation::EntityId)
                    .col(DocumentValidation::Source)
                    .col(DocumentValidation::Key)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(DocumentValidation::Table)
                    .name(Indexes::IdxDocumentValidationEntity.to_string())
                    .col(DocumentValidation::EntityType)
                    .col(DocumentValidation::EntityId)
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
                    .table(DocumentValidation::Table)
                    .name(Indexes::IdxDocumentValidationEntity.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(DocumentValidation::Table)
                    .name(Indexes::UqDocumentValidationSourceKey.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(DocumentValidation::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum DocumentValidation {
    Table,
    Id,
    EntityType,
    EntityId,
    Level,
    Message,
    Source,
    Key,
    Timestamp,
}

#[derive(DeriveIden)]
enum Indexes {
    UqDocumentValidationSourceKey,
    IdxDocumentValidationEntity,
}
