use sea_orm_migration::prelude::*;

/// A fully-unbounded version range (no low **and** no high bound) means "all
/// versions are affected" — e.g. a CSAF `known_affected` stated without a
/// version, a product CPE with version `*`, or an NVD affected CPE with no
/// version constraints. The per-scheme matchers historically returned `false`
/// for such a range, so those rows were silently dropped everywhere
/// `version_matches` runs (`/sbom/{id}/advisory`, `/purl`, `/analyze`),
/// producing false negatives (TC-5732 / scenario S11).
///
/// Fix: short-circuit at the top of the `version_matches` **dispatch** function
/// so a both-NULL range matches every version, uniformly across all schemes,
/// without touching the individual matcher bodies. Only the three-line guard is
/// new; the `CASE` below is the current dispatch body verbatim.
///
/// Backport note: the guard is branch-independent. When backporting to
/// release/0.4.z / 0.5.z / 0.6.z, keep the guard and use that branch's own
/// dispatch `CASE` (its set of supported schemes may differ).
#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"
CREATE OR REPLACE FUNCTION public.version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
    AS $$
declare
begin
    -- A fully-unbounded range (neither a low nor a high bound) means
    -- "all versions affected"; match every version regardless of scheme.
    if range_p.low_version is null and range_p.high_version is null then
        return true;
    end if;

    -- for an authoritative list of support schemes, see the enum
    -- `trustify_entity::version_scheme::VersionScheme`
    return case
        when range_p.version_scheme_id = 'git'
            then gitver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'semver'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'gem'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'npm'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'golang'
            then golang_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'nuget'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'generic'
            then generic_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'rpm'
            then rpmver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'maven'
            then maven_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'python'
            then python_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'packagist'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'hex'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'swift'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'pub'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'cargo'
            then semver_version_matches(version_p, range_p)
        else
            false
    end;
end
$$;
"#;

/// Restores the pre-fix dispatch (a fully-unbounded range yields whatever the
/// per-scheme matcher returns — historically `false`).
const DOWN: &str = r#"
CREATE OR REPLACE FUNCTION public.version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
    AS $$
declare
begin
    -- for an authoritative list of support schemes, see the enum
    -- `trustify_entity::version_scheme::VersionScheme`
    return case
        when range_p.version_scheme_id = 'git'
            then gitver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'semver'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'gem'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'npm'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'golang'
            then golang_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'nuget'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'generic'
            then generic_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'rpm'
            then rpmver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'maven'
            then maven_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'python'
            then python_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'packagist'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'hex'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'swift'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'pub'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'cargo'
            then semver_version_matches(version_p, range_p)
        else
            false
    end;
end
$$;
"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(DOWN).await?;
        Ok(())
    }
}
