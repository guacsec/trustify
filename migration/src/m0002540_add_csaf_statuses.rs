use sea_orm_migration::prelude::*;

/// Add the CSAF product statuses `first_affected`, `first_fixed` and `last_affected`, so that
/// ingestion can store them as stated. Their meaning as version ranges is derived by correlation
/// rules.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
INSERT INTO public.status VALUES
    ('b1d3e0c4-3f0a-4c1e-9a52-6f0e2b7c9a11', 'first_affected', 'First Affected', 'First version known to be affected by the vulnerability'),
    ('6a2f1d8e-0b3c-4e5f-8a7d-2c9b4e1f3a22', 'first_fixed', 'First Fixed', 'First version known to be fixed'),
    ('c4e8a1b2-7d5f-4a3c-9e6b-1f2d3c4b5a33', 'last_affected', 'Last Affected', 'Last version known to be affected by the vulnerability')
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
-- remediation links cascade
DELETE FROM public.purl_status WHERE status_id IN (
    SELECT id FROM public.status
    WHERE slug IN ('first_affected', 'first_fixed', 'last_affected')
);
DELETE FROM public.product_status WHERE status_id IN (
    SELECT id FROM public.status
    WHERE slug IN ('first_affected', 'first_fixed', 'last_affected')
);
DELETE FROM public.status WHERE slug IN ('first_affected', 'first_fixed', 'last_affected');
"#,
            )
            .await
            .map(|_| ())
    }
}
