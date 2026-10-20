use sea_orm_migration::prelude::*;

/// Options of the correlation engine, configurable per publisher, e.g. whether versionless PURLs
/// of a publisher's advisories mean "all versions". Comes with defaults.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
DO $$ BEGIN
    CREATE TYPE correlation_option_key AS ENUM ('versionless_purl', 'fixed_is_first_fixed');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS correlation_option (
    id                  UUID PRIMARY KEY,
    key                 correlation_option_key NOT NULL,
    publisher_namespace TEXT NOT NULL,
    value               JSONB NOT NULL,
    reason              TEXT,
    UNIQUE (key, publisher_namespace)
);

INSERT INTO correlation_option (id, key, publisher_namespace, value, reason) VALUES
    (
        '019dc7a4-6a00-7000-8000-000000000001',
        'versionless_purl',
        'https://www.redhat.com',
        'true',
        'Red Hat states the status of a component in a product with a versionless PURL, meaning all versions.'
    ),
    (
        '019dc7a4-6a00-7000-8000-000000000002',
        'versionless_purl',
        'https://www.suse.com',
        'true',
        'SUSE states the status of a package in a product with a versionless PURL, meaning all versions.'
    )
ON CONFLICT DO NOTHING;

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
        manager
            .get_connection()
            .execute_unprepared(
                r#"
DROP TABLE IF EXISTS correlation_option;
DROP TYPE IF EXISTS correlation_option_key;
"#,
            )
            .await
            .map(|_| ())
    }
}
