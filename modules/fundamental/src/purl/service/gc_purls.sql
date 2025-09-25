WITH
    alive_qualified_purl AS (
      (
        SELECT t2.id, t2.versioned_purl_id
        FROM sbom_package_purl_ref AS t1
                 INNER JOIN qualified_purl AS t2
                            ON t2.id = t1.qualified_purl_id
      )
      UNION
      (
        SELECT t1.id, t1.versioned_purl_id
        FROM qualified_purl AS t1
        INNER JOIN versioned_purl AS t2 ON t2.id = t1.versioned_purl_id
        INNER JOIN (
          SELECT DISTINCT base_purl_id
          FROM purl_status
        ) AS t3 ON t2.base_purl_id = t3.base_purl_id
      )
    ),
    alive_versioned_purl AS (
        SELECT DISTINCT t2.id, t2.base_purl_id
        FROM alive_qualified_purl AS t1
                 INNER JOIN versioned_purl AS t2
                            ON t2.id = t1.versioned_purl_id
    ),
    alive_base_purl AS (
        (
            SELECT t2.id
            FROM alive_versioned_purl AS t1
                     INNER JOIN base_purl AS t2 ON t2.id = t1.base_purl_id
        ) UNION (
            SELECT DISTINCT t2.id
            FROM purl_status AS t1
                     INNER JOIN base_purl AS t2 ON t2.id = t1.base_purl_id
        )
    ),
    dead_base_purl AS(
        (
            SELECT id FROM base_purl
        ) EXCEPT (
            SELECT id FROM alive_base_purl
        )
    ),
    dead_versioned_purl AS(
        (
            SELECT id FROM versioned_purl
        ) EXCEPT (
            SELECT id FROM alive_versioned_purl
        )
    ),
    dead_qualified_purl AS(
        (
            SELECT id FROM qualified_purl
        ) EXCEPT (
            SELECT id FROM alive_qualified_purl
        )
    ),
    deleted_base_purl AS (
        DELETE from base_purl
            WHERE id in (select id from dead_base_purl)
            returning 'base_purl', id
    ),
    deleted_versioned_purl AS (
        DELETE from versioned_purl
            WHERE id in (select id from dead_versioned_purl)
            returning 'versioned_purl', id
    ),
    deleted_qualified_purl AS (
        DELETE from qualified_purl
            WHERE id in (select id from dead_qualified_purl)
            returning 'qualified_purl', id
    ),
    deleted_records AS(
        (
            SELECT * from deleted_base_purl
        ) UNION (
            SELECT * from deleted_versioned_purl
        ) UNION (
            SELECT * from deleted_qualified_purl
        )
    )
SELECT * FROM deleted_records;
