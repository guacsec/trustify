use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"
CREATE OR REPLACE FUNCTION public.rpmver_cmp(a text, b text) RETURNS integer
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    a_epoch integer;
    b_epoch integer;
    a_segments text[];
    b_segments text[];
    a_len integer;
    b_len integer;
    a_seg text;
    b_seg text;
begin
    if a = b then return 0; end if;

    -- extract epoch (default 0 when omitted)
    a_epoch := 0;
    b_epoch := 0;
    if a ~ '^\d+:' then
        a_epoch := (regexp_match(a, '^(\d+):'))[1]::integer;
        a := substring(a from position(':' in a) + 1);
    end if;
    if b ~ '^\d+:' then
        b_epoch := (regexp_match(b, '^(\d+):'))[1]::integer;
        b := substring(b from position(':' in b) + 1);
    end if;
    if a_epoch > b_epoch then return 1; end if;
    if a_epoch < b_epoch then return -1; end if;

    a_segments := array(select (regexp_matches(a, '(\d+|[a-zA-Z]+|[~^])', 'g'))[1]);
    b_segments := array(select (regexp_matches(b, '(\d+|[a-zA-Z]+|[~^])', 'g'))[1]);
    a_len := array_length(a_segments, 1);
    b_len := array_length(b_segments, 1);
    for i in 1..coalesce(least(a_len, b_len), 0) loop
        a_seg = a_segments[i];
        b_seg = b_segments[i];
        if a_seg ~ '^\d' then
            if b_seg ~ '^\d' then
                a_seg := ltrim(a_seg, '0');
                b_seg := ltrim(b_seg, '0');
                case
                    when length(a_seg) > length(b_seg) then return 1;
                    when length(a_seg) < length(b_seg) then return -1;
                    else null;
                end case;
            else
                return 1;
            end if;
        elsif b_seg ~ '^\d' then
            return -1;
        elsif a_seg = '~' then
            if b_seg != '~' then
                return -1;
            end if;
        elsif b_seg = '~' then
            return 1;
        elsif a_seg = '^' then
            if b_seg != '^' then
                return -1;
            end if;
        elsif b_seg = '^' then
            return 1;
        end if;
        if a_seg != b_seg then
            if a_seg < b_seg then
                return -1;
            else
                return 1;
            end if;
        end if;
    end loop;
    if b_segments[a_len + 1] = '~' then return 1; end if;
    if a_segments[b_len + 1] = '~' then return -1; end if;
    if b_segments[a_len + 1] = '^' then return -1; end if;
    if a_segments[b_len + 1] = '^' then return 1; end if;
    if a_len > b_len then return 1; end if;
    if a_len < b_len then return -1; end if;
    return 0;
end $$;
"#;

const DOWN: &str = r#"
CREATE OR REPLACE FUNCTION public.rpmver_cmp(a text, b text) RETURNS integer
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
    a_segments text[];
    b_segments text[];
    a_len integer;
    b_len integer;
    a_seg text;
    b_seg text;
begin
    if a = b then return 0; end if;
    a_segments := array(select (regexp_matches(a, '(\d+|[a-zA-Z]+|[~^])', 'g'))[1]);
    b_segments := array(select (regexp_matches(b, '(\d+|[a-zA-Z]+|[~^])', 'g'))[1]);
    a_len := array_length(a_segments, 1);
    b_len := array_length(b_segments, 1);
    for i in 1..coalesce(least(a_len, b_len) + 1, 0) loop
        a_seg = a_segments[i];
        b_seg = b_segments[i];
        if a_seg ~ '^\d' then
            if b_seg ~ '^\d' then
                a_seg := ltrim(a_seg, '0');
                b_seg := ltrim(b_seg, '0');
                case
                    when length(a_seg) > length(b_seg) then return 1;
                    when length(a_seg) < length(b_seg) then return -1;
                    else null;
                end case;
            else
                return 1;
            end if;
        elsif b_seg ~ '^\d' then
            return -1;
        elsif a_seg = '~' then
            if b_seg != '~' then
                return -1;
            end if;
        elsif b_seg = '~' then
            return 1;
        elsif a_seg = '^' then
            if b_seg != '^' then
                return 1;
            end if;
        elsif b_seg = '^' then
            return -1;
        end if;
        if a_seg != b_seg then
            if a_seg < b_seg then
                return -1;
            else
                return 1;
            end if;
        end if;
    end loop;
    if b_segments[a_len + 1] = '~' then return 1; end if;
    if a_segments[b_len + 1] = '~' then return -1; end if;
    if b_segments[a_len + 1] = '^' then return -1; end if;
    if a_segments[b_len + 1] = '^' then return 1; end if;
    if a_len > b_len then return 1; end if;
    if a_len < b_len then return -1; end if;
    return 0;
end $$;
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
