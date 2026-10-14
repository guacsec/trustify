use sea_orm_migration::prelude::*;

/// Wildcards in upper bounds of version ranges, as a CVE record states them.
///
/// A CVE `lessThan` (or `lessThanOrEqual`) may end in `*`, "indicating an arbitrarily large number
/// in the version ordering": `*` means no upper bound, `1.*` the whole `1.` branch. Ingestion stores
/// the stated bound, `version_matches()` evaluates it: `P.*` matches a version up to and including
/// `P`, or starting with `P.`, independent of the versioning scheme.
#[derive(DeriveMigrationName)]
pub struct Migration;

/// The dispatch to the versioning schemes, as of `m0002080_add_cargo_version_scheme`.
const DISPATCH: &str = r#"
    return case
        when range_p.version_scheme_id = 'git'
            -- Git is git, and hard.
            then gitver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'semver'
            -- Semver is semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'gem'
            -- RubyGems claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'npm'
            -- NPM claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'golang'
            -- Golang claims to be semver
            then golang_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'nuget'
            -- NuGet claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'generic'
            -- Just check if it is equal
            then generic_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'rpm'
            -- Look at me! I'm an RPM! I'm special!
            then rpmver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'maven'
            -- Look at me! I'm a Maven! I'm kinda special!
            then maven_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'python'
            -- Python versioning
            then python_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'packagist'
            -- Packagist PHP strongly encourages semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'hex'
            -- Erlang Hex claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'swift'
            -- Swift Package Manager claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'pub'
            -- Pub Dart Flutter claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'cargo'
            -- Cargo crates.io uses semver
            then semver_version_matches(version_p, range_p)
        else
            false
    end;
"#;

/// The wildcard handling, before the dispatch.
const WILDCARD: &str = r#"
    if right(range_p.high_version, 1) = '*' then
        if range_p.high_version = '*' then
            -- no upper bound
            range_p.high_version := null;
            range_p.high_inclusive := false;
        else
            -- `P.*`: up to and including `P`, or within its branch (starting with `P.`)
            prefix := left(range_p.high_version, -1);
            return version_matches(
                    version_p,
                    ROW(
                        range_p.id, range_p.version_scheme_id,
                        range_p.low_version, range_p.low_inclusive, null, false
                    )::public.version_range
                )
                and (
                    starts_with(version_p, prefix)
                    or version_matches(
                        version_p,
                        ROW(
                            range_p.id, range_p.version_scheme_id,
                            null, false, rtrim(prefix, '.-_+~'), true
                        )::public.version_range
                    )
                );
        end if;
    end if;
"#;

fn function(wildcard: &str) -> String {
    format!(
        r#"
CREATE OR REPLACE FUNCTION public.version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
    AS $$
declare
    prefix text;
begin
{wildcard}
{DISPATCH}
end
$$;
"#
    )
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&function(WILDCARD))
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&function(""))
            .await
            .map(|_| ())
    }
}
