use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const FUNCTIONS: &[(&str, &str, &str)] = &[
    (
        "public.rpmver_cmp(text, text)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.rpmver_version_matches(text, public.version_range)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.mavenver_cmp(text, text)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.maven_version_matches(text, public.version_range)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.semver_cmp(text, text)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.semver_version_matches(text, public.version_range)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.generic_version_matches(text, public.version_range)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.gitver_version_matches(text, public.version_range)",
        "IMMUTABLE PARALLEL UNSAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.golang_version_matches(text, public.version_range)",
        "IMMUTABLE PARALLEL UNSAFE",
        "IMMUTABLE PARALLEL SAFE",
    ),
    (
        "public.pythonver_cmp(text, text)",
        "IMMUTABLE PARALLEL RESTRICTED",
        "IMMUTABLE PARALLEL RESTRICTED",
    ),
    (
        "public.python_version_matches(text, public.version_range)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL RESTRICTED",
    ),
    (
        "public.version_matches(text, public.version_range)",
        "IMMUTABLE PARALLEL SAFE",
        "IMMUTABLE PARALLEL RESTRICTED",
    ),
];

async fn apply_modifiers(manager: &SchemaManager<'_>, use_after: bool) -> Result<(), DbErr> {
    for (signature, before, after) in FUNCTIONS {
        let modifiers = if use_after { after } else { before };
        let sql = format!("ALTER FUNCTION {signature} {modifiers};");
        manager.get_connection().execute_unprepared(&sql).await?;
    }

    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        apply_modifiers(manager, true).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        apply_modifiers(manager, false).await
    }
}
