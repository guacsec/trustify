use sea_orm_migration::prelude::*;

/// Rewrites Quay importer JSONB configurations to replace the legacy
/// `apiToken` field with the new unified `auth` credential structure.
///
/// The `auth` field uses a Bearer + Inline credential source so that
/// existing plaintext tokens continue to work unchanged after upgrade.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
UPDATE importer
SET configuration = jsonb_set(
    configuration - 'apiToken',
    '{auth}',
    jsonb_build_object(
        'method', jsonb_build_object(
            'type', 'bearer',
            'token', jsonb_build_object(
                'type', 'inline',
                'value', configuration->>'apiToken'
            )
        )
    )
)
WHERE configuration->>'type' = 'quay'
  AND configuration->>'apiToken' IS NOT NULL;
"#,
            )
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
UPDATE importer
SET configuration = jsonb_set(
    configuration - 'auth',
    '{apiToken}',
    to_jsonb(configuration->'auth'->'method'->'token'->>'value')
)
WHERE configuration->>'type' = 'quay'
  AND configuration->'auth'->'method'->>'type' = 'bearer'
  AND configuration->'auth'->'method'->'token'->>'type' = 'inline'
  AND configuration->'auth'->'method'->'token'->>'value' IS NOT NULL;
"#,
            )
            .await
            .map(|_| ())
    }
}
