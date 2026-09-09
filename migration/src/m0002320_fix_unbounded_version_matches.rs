use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"
CREATE OR REPLACE FUNCTION public.generic_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
begin
    if range_p.low_version is null and range_p.high_version is null then
        return true;
    end if;

    if range_p.low_version is not null then
        if range_p.low_inclusive then
            if version_p = range_p.low_version then
                return true;
            end if;
        end if;
    end if;

    if range_p.high_version is not null then
        if range_p.high_inclusive then
            if version_p = range_p.high_version  then
                return true;
            end if;
        end if;
    end if;

    return false;

end
$$;

CREATE OR REPLACE FUNCTION public.gitver_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
begin
    if range_p.low_version is null and range_p.high_version is null then
        return true;
    end if;

    if range_p.low_version is not null then
        if range_p.low_inclusive then
            if version_p = range_p.low_version then
                return true;
            end if;
        end if;
    end if;

    if range_p.high_version is not null then
        if range_p.high_inclusive then
            if version_p = range_p.high_version  then
                return true;
            end if;
        end if;
    end if;

    return false;

end
$$;

CREATE OR REPLACE FUNCTION public.maven_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is null and range_p.high_version is null then
        return true;
    end if;

    if range_p.low_version is not null then
        low_end := mavenver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := mavenver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$;

CREATE OR REPLACE FUNCTION public.python_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is null and range_p.high_version is null then
        return true;
    end if;

    if range_p.low_version is not null then
        low_end := pythonver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := pythonver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$;

CREATE OR REPLACE FUNCTION public.rpmver_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is null and range_p.high_version is null then
        return true;
    end if;

    if range_p.low_version is not null then
        low_end := rpmver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := rpmver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$;

CREATE OR REPLACE FUNCTION public.semver_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is null and range_p.high_version is null then
        return true;
    end if;

    if range_p.low_version is not null then
        low_end := semver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := semver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$;
"#;

const DOWN: &str = r#"
CREATE OR REPLACE FUNCTION public.generic_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
begin
    if range_p.low_version is not null then
        if range_p.low_inclusive then
            if version_p = range_p.low_version then
                return true;
            end if;
        end if;
    end if;

    if range_p.high_version is not null then
        if range_p.high_inclusive then
            if version_p = range_p.high_version  then
                return true;
            end if;
        end if;
    end if;

    return false;

end
$$;

CREATE OR REPLACE FUNCTION public.gitver_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
begin
    if range_p.low_version is not null then
        if range_p.low_inclusive then
            if version_p = range_p.low_version then
                return true;
            end if;
        end if;
    end if;

    if range_p.high_version is not null then
        if range_p.high_inclusive then
            if version_p = range_p.high_version  then
                return true;
            end if;
        end if;
    end if;

    return false;

end
$$;

CREATE OR REPLACE FUNCTION public.maven_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is not null then
        low_end := mavenver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := mavenver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$;

CREATE OR REPLACE FUNCTION public.python_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is not null then
        low_end := pythonver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := pythonver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$;

CREATE OR REPLACE FUNCTION public.rpmver_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is not null then
        low_end := rpmver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := rpmver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$;

CREATE OR REPLACE FUNCTION public.semver_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is not null then
        low_end := semver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := semver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$;
"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(UP)
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(DOWN)
            .await
            .map(|_| ())
    }
}
