use sea_orm_migration::prelude::*;

/// Add the `custom` version scheme: a CVE `versionType` of `custom`, a version range whose
/// versioning scheme is unspecified. `version_matches()` doesn't know it, so such a range only
/// matches through a correlation rule which picks a scheme.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
INSERT INTO public.version_scheme VALUES (
    'custom',
    'CVE custom version type',
    'A version range of an unspecified versioning scheme, see https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json'
) ON CONFLICT DO NOTHING;
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
DELETE FROM public.remediation_purl_status WHERE purl_status_id IN (
    SELECT ps.id FROM public.purl_status ps
    JOIN public.version_range vr ON vr.id = ps.version_range_id
    WHERE vr.version_scheme_id = 'custom'
);
DELETE FROM public.purl_status WHERE version_range_id IN (
    SELECT id FROM public.version_range WHERE version_scheme_id = 'custom'
);
DELETE FROM public.cpe_status WHERE version_range_id IN (
    SELECT id FROM public.version_range WHERE version_scheme_id = 'custom'
);
DELETE FROM public.advisory_vulnerability_cpe WHERE version_range_id IN (
    SELECT id FROM public.version_range WHERE version_scheme_id = 'custom'
);
DELETE FROM public.advisory_vulnerability_product_identifier WHERE version_range_id IN (
    SELECT id FROM public.version_range WHERE version_scheme_id = 'custom'
);
DELETE FROM public.version_range WHERE version_scheme_id = 'custom';
DELETE FROM public.version_scheme WHERE id = 'custom';
"#,
            )
            .await
            .map(|_| ())
    }
}
