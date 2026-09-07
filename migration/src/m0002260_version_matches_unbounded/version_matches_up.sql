--
-- Make a fully-unbounded version range (both bounds NULL) match any version.
--
-- A bare CSAF `known_affected` (version-less) is stored as an unbounded range
-- (see modules/ingestor/src/service/advisory/csaf/creator.rs and
-- .../csaf/product_status.rs, which emit VersionSpec::Range(Unbounded, Unbounded)).
-- The per-scheme comparators (rpmver/semver/maven/python) return FALSE when both
-- bounds are NULL, so those assertions never matched -> genuine vulnerabilities
-- were silently missed (false negative, TC-5732).
--
-- Guard for it here in the dispatcher, before delegating to the scheme-specific
-- comparators, so the fix applies uniformly across all schemes. This keys off
-- the stored bounds being NULL (not the comparison result), so ranges that carry
-- a bound that merely fails to parse are unaffected and still flow through to the
-- comparators (which continue to return FALSE for them).
--
CREATE OR REPLACE FUNCTION public.version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
begin
    -- A fully-unbounded range means "all versions" (e.g. a bare, version-less
    -- known_affected). Without this, every per-scheme comparator returns false
    -- for a (NULL, NULL) range and the assertion is unmatchable. See TC-5732.
    if range_p.low_version is null and range_p.high_version is null then
        return true;
    end if;

    -- for an authoritative list of support schemes, see the enum
    -- `trustify_entity::version_scheme::VersionScheme`
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
        else
            false
    end;
end
$$;
