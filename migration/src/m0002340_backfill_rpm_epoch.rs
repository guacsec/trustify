use sea_orm::{
    ConnectionTrait, DatabaseBackend, EntityTrait, FromQueryResult, Set, Statement,
    sea_query::OnConflict,
};
use sea_orm_migration::prelude::*;
use std::collections::BTreeMap;
use trustify_common::{db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::versioned_purl;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Debug, FromQueryResult)]
struct RpmEpochRow {
    qp_id: Uuid,
    epoch: String,
    vp_version: String,
    base_purl_id: Uuid,
    bp_type: String,
    bp_namespace: Option<String>,
    bp_name: String,
}

const PAGE_SIZE: u64 = 5000;

const SELECT_RPM_EPOCH_PAGE: &str = r#"
SELECT
    qp.id AS qp_id,
    qp.qualifiers->>'epoch' AS epoch,
    vp.version AS vp_version,
    vp.base_purl_id,
    bp.type AS bp_type,
    bp.namespace AS bp_namespace,
    bp.name AS bp_name
FROM qualified_purl qp
JOIN versioned_purl vp ON vp.id = qp.versioned_purl_id
JOIN base_purl bp ON bp.id = vp.base_purl_id
WHERE bp.type = 'rpm'
  AND qp.qualifiers->>'epoch' IS NOT NULL
  AND qp.qualifiers->>'epoch' != '0'
  AND vp.version !~ '^\d+:'
LIMIT $1
"#;

const DELETE_ORPHANED_VERSIONED_PURLS: &str = r#"
DELETE FROM versioned_purl vp
USING base_purl bp
WHERE bp.id = vp.base_purl_id
  AND bp.type = 'rpm'
  AND vp.version !~ '^\d+:'
  AND NOT EXISTS (
      SELECT 1 FROM qualified_purl qp WHERE qp.versioned_purl_id = vp.id
  )
"#;

async fn process_page(
    conn: &SchemaManagerConnection<'_>,
    rows: &[RpmEpochRow],
) -> Result<(), DbErr> {
    let mut new_versioned = std::collections::HashMap::<Uuid, versioned_purl::ActiveModel>::new();
    let mut qp_updates = Vec::<(Uuid, Uuid)>::with_capacity(rows.len());

    for row in rows {
        let purl = Purl {
            ty: row.bp_type.clone(),
            namespace: row.bp_namespace.clone(),
            name: row.bp_name.clone(),
            version: Some(row.vp_version.clone()),
            qualifiers: BTreeMap::from([("epoch".to_string(), row.epoch.clone())]),
        };

        let new_vp_id = purl.version_uuid();
        let new_version = purl.effective_version();

        new_versioned
            .entry(new_vp_id)
            .or_insert_with(|| versioned_purl::ActiveModel {
                id: Set(new_vp_id),
                base_purl_id: Set(row.base_purl_id),
                version: Set(new_version),
            });

        qp_updates.push((row.qp_id, new_vp_id));
    }

    let batches: Vec<Vec<_>> = new_versioned
        .into_values()
        .chunked()
        .into_iter()
        .map(|chunk| chunk.collect())
        .collect();

    for batch in batches {
        versioned_purl::Entity::insert_many(batch)
            .on_conflict(
                OnConflict::columns([versioned_purl::Column::Id])
                    .do_nothing()
                    .to_owned(),
            )
            .do_nothing()
            .exec(conn)
            .await?;
    }

    for (qp_id, new_vp_id) in &qp_updates {
        conn.execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "UPDATE qualified_purl SET versioned_purl_id = $1 WHERE id = $2",
            [(*new_vp_id).into(), (*qp_id).into()],
        ))
        .await?;
    }

    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // Prevent concurrent writes while we page through and repoint rows.
        conn.execute_unprepared("LOCK TABLE qualified_purl, versioned_purl IN EXCLUSIVE MODE")
            .await?;

        loop {
            let rows = RpmEpochRow::find_by_statement(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                SELECT_RPM_EPOCH_PAGE,
                [PAGE_SIZE.into()],
            ))
            .all(conn)
            .await?;

            if rows.is_empty() {
                break;
            }

            process_page(conn, &rows).await?;
        }

        conn.execute_unprepared(DELETE_ORPHANED_VERSIONED_PURLS)
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
