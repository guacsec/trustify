use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ChangeLog::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ChangeLog::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ChangeLog::EntityType).text().not_null())
                    .col(ColumnDef::new(ChangeLog::EntityId).uuid())
                    .col(ColumnDef::new(ChangeLog::Operation).text().not_null())
                    .col(
                        ColumnDef::new(ChangeLog::CreatedAt)
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
                    .table(ChangeLog::Table)
                    .name(Indexes::IdxChangeLogCreatedAt.to_string())
                    .col(ChangeLog::CreatedAt)
                    .to_owned(),
            )
            .await?;

        // Trigger function that notifies listeners on INSERT
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE OR REPLACE FUNCTION notify_change_log() RETURNS trigger AS $$
                BEGIN
                    PERFORM pg_notify('trustify_changes', json_build_object(
                        'id', NEW.id,
                        'entity_type', NEW.entity_type,
                        'entity_id', NEW.entity_id,
                        'operation', NEW.operation
                    )::text);
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
                "#,
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TRIGGER change_log_notify
                    AFTER INSERT ON change_log
                    FOR EACH ROW
                    EXECUTE FUNCTION notify_change_log()
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TRIGGER IF EXISTS change_log_notify ON change_log")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("DROP FUNCTION IF EXISTS notify_change_log()")
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(ChangeLog::Table)
                    .name(Indexes::IdxChangeLogCreatedAt.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().if_exists().table(ChangeLog::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ChangeLog {
    Table,
    Id,
    EntityType,
    EntityId,
    Operation,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Indexes {
    IdxChangeLogCreatedAt,
}
