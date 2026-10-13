use sea_orm_migration::prelude::*;

/// Views adding the `affected` statuses which a publisher's `fixed` implies (correlation option
/// `fixed_is_first_fixed`) at query time, as a bridge for the fundamental APIs.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002560_purl_status_effective/up.sql"))
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002560_purl_status_effective/down.sql"))
            .await
            .map(|_| ())
    }
}
