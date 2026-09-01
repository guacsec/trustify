use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const ENSURE_UUID_OSSP: &str = r#"CREATE EXTENSION IF NOT EXISTS "uuid-ossp""#;

// Compute new versioned_purl UUIDs using the same UUID v5 chain as Rust:
//   package_uuid = uuid_v5(uuid_v5(uuid_v5(NAMESPACE, type), namespace?), name)
//   new_id       = uuid_v5(package_uuid, epoch || ':' || version)
const INSERT_NEW_VERSIONED_PURLS: &str = r#"
INSERT INTO versioned_purl (id, base_purl_id, version)
SELECT DISTINCT
    CASE
        WHEN bp.namespace IS NOT NULL THEN
            uuid_generate_v5(
                uuid_generate_v5(
                    uuid_generate_v5(
                        uuid_generate_v5('3738b43d-fd03-4a9d-849c-489bec610f06'::uuid, bp.type),
                        bp.namespace),
                    bp.name),
                (qp.qualifiers->>'epoch') || ':' || vp.version)
        ELSE
            uuid_generate_v5(
                uuid_generate_v5(
                    uuid_generate_v5('3738b43d-fd03-4a9d-849c-489bec610f06'::uuid, bp.type),
                    bp.name),
                (qp.qualifiers->>'epoch') || ':' || vp.version)
    END,
    vp.base_purl_id,
    (qp.qualifiers->>'epoch') || ':' || vp.version
FROM qualified_purl qp
JOIN versioned_purl vp ON vp.id = qp.versioned_purl_id
JOIN base_purl bp ON bp.id = vp.base_purl_id
WHERE bp.type = 'rpm'
  AND qp.qualifiers->>'epoch' IS NOT NULL
  AND qp.qualifiers->>'epoch' != '0'
  AND vp.version !~ '^\d+:'
ON CONFLICT (id) DO NOTHING
"#;

const REPOINT_QUALIFIED_PURLS: &str = r#"
UPDATE qualified_purl qp
SET versioned_purl_id = CASE
    WHEN bp.namespace IS NOT NULL THEN
        uuid_generate_v5(
            uuid_generate_v5(
                uuid_generate_v5(
                    uuid_generate_v5('3738b43d-fd03-4a9d-849c-489bec610f06'::uuid, bp.type),
                    bp.namespace),
                bp.name),
            (qp.qualifiers->>'epoch') || ':' || vp.version)
    ELSE
        uuid_generate_v5(
            uuid_generate_v5(
                uuid_generate_v5('3738b43d-fd03-4a9d-849c-489bec610f06'::uuid, bp.type),
                bp.name),
            (qp.qualifiers->>'epoch') || ':' || vp.version)
END
FROM versioned_purl vp
JOIN base_purl bp ON bp.id = vp.base_purl_id
WHERE qp.versioned_purl_id = vp.id
  AND bp.type = 'rpm'
  AND qp.qualifiers->>'epoch' IS NOT NULL
  AND qp.qualifiers->>'epoch' != '0'
  AND vp.version !~ '^\d+:'
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

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(ENSURE_UUID_OSSP).await?;
        conn.execute_unprepared(INSERT_NEW_VERSIONED_PURLS).await?;
        conn.execute_unprepared(REPOINT_QUALIFIED_PURLS).await?;
        conn.execute_unprepared(DELETE_ORPHANED_VERSIONED_PURLS)
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
