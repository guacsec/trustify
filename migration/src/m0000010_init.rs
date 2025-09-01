use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// This migration squashes MANY previous migrations.  If you need to write a new one,
// and you would like to see some examples of how they were written, you can browse those previous migrations at:
// https://github.com/guacsec/trustify/tree/3d6eaa3c44558201c735b755f26596d9778bc111/migration/src
#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // the data for this migration extracted using:
        //     pg_dump --no-owner --clean --no-privileges --inserts --exclude-table-and-children=seaql_migrations -U postgres trustify > migration/src/m0000010_init_up.sql
        // Delete the SET statements at the start of the file
        // Move the drop statements at the start to m0000010_init_down.sql

        let x = manager
            .get_connection()
            .execute_unprepared(include_str!("m0000010_init_up.sql"))
            .await
            .map(|_| ());
        x?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000010_init_down.sql"))
            .await
            .map(|_| ())?;
        Ok(())
    }
}
