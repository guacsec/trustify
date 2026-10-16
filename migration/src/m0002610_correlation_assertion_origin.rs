use sea_orm_migration::prelude::*;

/// Record provenance for evidence produced before extractors recorded it themselves.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
WITH origins AS (
    SELECT id, CASE
        WHEN extractor IN ('purl', 'purl_stream', 'purl_vls_range', 'purl_custom_range',
                           'cpe', 'digest', 'product_identifier', 'purl_first_fixed',
                           'purl_first_affected', 'purl_last_affected') THEN 'stated'
        WHEN extractor IN ('purl_default', 'cpe_default') THEN 'default'
        WHEN extractor IN ('purl_fixed_as_first_fixed', 'purl_fixed_as_first_fixed_before',
                           'purl_any_version') THEN 'publisher_policy'
        WHEN extractor IN ('purl_first_fixed_before', 'purl_suse_recommended',
                           'purl_suse_recommended_before') THEN 'inferred'
    END AS origin
    FROM correlation_evidence
    WHERE matched_value IS NULL OR
          (jsonb_typeof(matched_value) = 'object' AND NOT matched_value ? 'origin')
)
UPDATE correlation_evidence AS evidence
SET matched_value = COALESCE(evidence.matched_value, '{"identifier":""}'::jsonb)
                    || jsonb_build_object('origin', origins.origin)
FROM origins
WHERE evidence.id = origins.id AND origins.origin IS NOT NULL
"#,
            )
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE correlation_evidence SET matched_value = matched_value - 'origin' \
                 WHERE jsonb_typeof(matched_value) = 'object' AND matched_value ? 'origin'",
            )
            .await
            .map(|_| ())
    }
}
