use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "
                    CREATE OR REPLACE FUNCTION public.encode_uri_component(text) RETURNS text
                        LANGUAGE sql IMMUTABLE STRICT
                        AS $_$
                        SELECT string_agg(
                            CASE
                                WHEN bytes > 1 or c !~ '[0-9a-zA-Z_.!~*''()-]+' THEN
                                    regexp_replace(encode(convert_to(c, 'utf-8')::bytea, 'hex'), '(..)', E'%\\1', 'g')
                                ELSE
                                    c
                                END,
                            ''
                        )
                        FROM (
                            SELECT c, octet_length(c) bytes
                            FROM regexp_split_to_table($1, '') c
                        ) q;
                    $_$;

                    CREATE OR REPLACE FUNCTION public.get_purl(qualified_purl_id uuid)
                    RETURNS text
                    LANGUAGE sql IMMUTABLE PARALLEL SAFE
                    AS $$
                        SELECT COALESCE(
                                'pkg:'
                                || COALESCE(purl ->> 'ty','')
                                || REPLACE(('/' || COALESCE(purl ->> 'namespace','') || '/'), '//', '/')
                                || encode_uri_component(COALESCE(purl ->> 'name',''))
                                || '@' || encode_uri_component(COALESCE(purl ->> 'version',''))
                                || COALESCE(
                                    '?' || string_agg(key || '=' || encode_uri_component(value), '&')
                                    FILTER (WHERE qualifiers IS NOT NULL AND qualifiers <> '{}'::jsonb),
                                    ''
                                ),
                                qualified_purl_id::text
                            )
                        FROM qualified_purl
                        LEFT JOIN LATERAL jsonb_each_text(qualifiers) AS qualifiers(key, value)
                          ON TRUE
                        WHERE id = qualified_purl_id
                        GROUP BY purl, qualifiers;
                    $$;
                ",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "
                    DROP FUNCTION public.get_purl(qualified_purl_id uuid);
                    DROP FUNCTION public.encode_uri_component(text);
                ",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }
}
