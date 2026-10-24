use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        conn.execute_unprepared(
            "ALTER TABLE crypto_remediation \
             ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        )
        .await?;

        // Trigger keeps updated_at current on every row update regardless of which
        // application version writes the row (important during rolling deployments).
        conn.execute_unprepared(
            "CREATE OR REPLACE FUNCTION crypto_remediation_set_updated_at() \
             RETURNS TRIGGER LANGUAGE plpgsql AS $$ \
             BEGIN NEW.updated_at = NOW(); RETURN NEW; END; $$",
        )
        .await?;

        conn.execute_unprepared(
            "CREATE OR REPLACE TRIGGER crypto_remediation_updated_at \
             BEFORE UPDATE ON crypto_remediation \
             FOR EACH ROW EXECUTE FUNCTION crypto_remediation_set_updated_at()",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        conn.execute_unprepared(
            "DROP TRIGGER IF EXISTS crypto_remediation_updated_at ON crypto_remediation",
        )
        .await?;

        conn.execute_unprepared("DROP FUNCTION IF EXISTS crypto_remediation_set_updated_at()")
            .await?;

        conn.execute_unprepared("ALTER TABLE crypto_remediation DROP COLUMN IF EXISTS updated_at")
            .await?;

        Ok(())
    }
}
