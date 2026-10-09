use sea_orm_migration::prelude::*;

/// The correlation option `fixed_is_first_fixed`: a publisher's `fixed` means `first_fixed`.
/// Enabled for Red Hat by default.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // a value added by `ALTER TYPE … ADD VALUE` can't be used in the same transaction, the
        // default option below does: recreate the type with it
        manager
            .get_connection()
            .execute_unprepared(
                r#"
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'correlation_option_key' AND e.enumlabel = 'fixed_is_first_fixed'
    ) THEN
        ALTER TYPE correlation_option_key RENAME TO correlation_option_key_old;
        CREATE TYPE correlation_option_key AS ENUM ('versionless_purl', 'fixed_is_first_fixed');
        ALTER TABLE correlation_option
            ALTER COLUMN key TYPE correlation_option_key
            USING key::text::correlation_option_key;
        DROP TYPE correlation_option_key_old;
    END IF;
END $$;

INSERT INTO correlation_option (id, key, publisher_namespace, value, reason) VALUES (
    '019dc7a4-6a00-7000-8000-000000000003',
    'fixed_is_first_fixed',
    'https://www.redhat.com',
    'true',
    'Red Hat states `fixed` only for the build fixing a vulnerability in a product stream: earlier builds of the stream are affected, later ones are fixed.'
)
ON CONFLICT DO NOTHING;
"#,
            )
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // values can't be removed from an enum: recreate it without them
        manager
            .get_connection()
            .execute_unprepared(
                r#"
DELETE FROM correlation_option WHERE key::text = 'fixed_is_first_fixed';
ALTER TYPE correlation_option_key RENAME TO correlation_option_key_old;
CREATE TYPE correlation_option_key AS ENUM ('versionless_purl');
ALTER TABLE correlation_option
    ALTER COLUMN key TYPE correlation_option_key
    USING key::text::correlation_option_key;
DROP TYPE correlation_option_key_old;
"#,
            )
            .await
            .map(|_| ())
    }
}
