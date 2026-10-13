use sea_orm_migration::prelude::*;

/// The default status of a CVE record: a flag on `purl_status` and `advisory_vulnerability_cpe`,
/// left out of the fundamental APIs' bridge view.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002590_default_status/up.sql"))
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared(include_str!("m0002590_default_status/down.sql"))
            .await?;
        // the view as before
        connection
            .execute_unprepared(include_str!("m0002560_purl_status_effective/up.sql"))
            .await
            .map(|_| ())
    }
}
