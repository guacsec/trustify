//! Replaces the `status` lookup table with a PostgreSQL enum backed by SeaORM's
//! `DeriveActiveEnum`, across `purl_status`, `product_status` and `cpe_status`.
//!
//! Beyond the schema swap this migration also recomputes the primary keys of
//! those three tables **in place**. Their ids are a chain of `Uuid::new_v5`
//! hashes whose first link used to be the status *UUID* bytes and is now the
//! status *slug* string (see the `*_status_id` free functions in
//! `trustify-module-ingestor`). Every hashed input is a stored column, so the
//! migration reconstructs nothing — it reads each row, recomputes the id with
//! the exact same function the ingestor uses, and rewrites it, cascading to the
//! `remediation_purl_status` / `remediation_product_status` children
//! (`cpe_status` has no remediation child).
//!
//! The old seed contained two different `fixed` rows (`m0000010_init_up.sql`),
//! so post-recompute two previously distinct rows can collapse onto one id.
//! That collision is deduplicated here (survivor = smallest old id); it is the
//! main thing this migration adds over a naive schema swap. Because
//! `product_status.csaf_product_ids` is not part of the id hash, colliding
//! `product_status` rows can differ there, so that column is unioned into the
//! survivor rather than lost with the deleted duplicate.

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;
use std::collections::HashMap;
use trustify_common::db::create_enum_if_not_exists;
use trustify_module_ingestor::graph::advisory::{
    cpe_status::cpe_status_id, product_status::product_status_id, purl_status::purl_status_id,
};
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

// The enum's Postgres type name and variants as `DeriveIden`s for the schema
// builder. `create_enum_if_not_exists` needs iden values, whereas
// `trustify_entity::status::Status` is a `DeriveActiveEnum` value type, so the
// names are restated here.
#[derive(Clone, DeriveIden)]
enum StatusEnum {
    #[sea_orm(iden = "status")]
    Table,
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
    Recommended,
}

/// The enum's value variants (everything except `Table`), in declaration order.
///
/// Single source of truth: `up()`'s `create_enum_if_not_exists` call builds the
/// Postgres type from exactly this list, and the `status_enum_matches_entity_variants`
/// test checks *this same list* against `entity::status::Status`. Deriving both
/// from one array is what makes the drift test meaningful — a variant added to
/// the entity but forgotten here fails the test, and a variant added here that
/// isn't in the entity does too. (The entity's own `status_serialization_alignment`
/// test only covers the SeaORM/strum/serde contract *within* the entity, not this
/// migration's separately-declared copy.)
fn status_enum_variants() -> [StatusEnum; 5] {
    [
        StatusEnum::Affected,
        StatusEnum::Fixed,
        StatusEnum::NotAffected,
        StatusEnum::UnderInvestigation,
        StatusEnum::Recommended,
    ]
}

/// A `remediation_*_status` child whose FK to a status table's `id` must follow
/// the recomputed parent keys.
struct ChildFk {
    /// The child table (composite PK `(owner_col, fk_col)`).
    table: &'static str,
    /// The child column referencing the parent `id`.
    fk_col: &'static str,
    /// The other half of the child's composite PK.
    owner_col: &'static str,
    /// Name to give the re-added FK constraint.
    new_fk_name: &'static str,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 1. Add temporary text columns to hold migrated status slugs. We can't
        //    create the enum type yet because the status TABLE occupies the name.
        conn.execute_unprepared(
            r#"
            ALTER TABLE purl_status    ADD COLUMN IF NOT EXISTS status_text text;
            ALTER TABLE product_status ADD COLUMN IF NOT EXISTS status_text text;
            ALTER TABLE cpe_status     ADD COLUMN IF NOT EXISTS status_text text;
            "#,
        )
        .await?;

        // 2. Migrate data from the old status table via slug-based join. The
        //    duplicate "fixed" UUIDs both map to the same slug here.
        conn.execute_unprepared(
            r#"
            UPDATE purl_status    SET status_text = s.slug FROM status s
                WHERE s.id = purl_status.status_id    AND purl_status.status_text    IS NULL;
            UPDATE product_status SET status_text = s.slug FROM status s
                WHERE s.id = product_status.status_id AND product_status.status_text IS NULL;
            UPDATE cpe_status     SET status_text = s.slug FROM status s
                WHERE s.id = cpe_status.status_id     AND cpe_status.status_text     IS NULL;
            "#,
        )
        .await?;

        // 2b. Validate that all rows were migrated — fail early if orphaned
        //     status_id references left NULL status_text values.
        conn.execute_unprepared(
            r#"
            DO $$
            DECLARE
                null_purl_count bigint;
                null_product_count bigint;
                null_cpe_count bigint;
            BEGIN
                SELECT count(*) INTO null_purl_count    FROM purl_status    WHERE status_text IS NULL;
                SELECT count(*) INTO null_product_count FROM product_status WHERE status_text IS NULL;
                SELECT count(*) INTO null_cpe_count     FROM cpe_status     WHERE status_text IS NULL;
                IF null_purl_count > 0 OR null_product_count > 0 OR null_cpe_count > 0 THEN
                    RAISE EXCEPTION 'Migration blocked: % purl_status, % product_status, % cpe_status rows have NULL status_text (orphaned status_id references)',
                        null_purl_count, null_product_count, null_cpe_count;
                END IF;
            END$$;
            "#,
        )
        .await?;

        // 3. Recompute primary keys in place. The slug (in status_text) now
        //    drives the v5 hash; recompute every id with the same function the
        //    ingestor uses and cascade to the remediation children. All hash
        //    inputs are still present (status_id is dropped only in step 4).
        let purl_remap = mark_survivors(compute_purl_status_remap(conn).await?);
        apply_remap(
            conn,
            "purl_status",
            purl_remap,
            Some(ChildFk {
                table: "remediation_purl_status",
                fk_col: "purl_status_id",
                owner_col: "remediation_id",
                new_fk_name: "remediation_purl_status_purl_status_id_fkey",
            }),
            &[],
        )
        .await?;

        let product_remap = mark_survivors(compute_product_status_remap(conn).await?);
        apply_remap(
            conn,
            "product_status",
            product_remap,
            Some(ChildFk {
                table: "remediation_product_status",
                fk_col: "product_status_id",
                owner_col: "remediation_id",
                new_fk_name: "remediation_product_status_product_status_id_fkey",
            }),
            // csaf_product_ids is not part of the id hash, so colliding rows can
            // differ; union it into the survivor rather than lose the loser's.
            &["csaf_product_ids"],
        )
        .await?;

        // cpe_status has no remediation child FK.
        let cpe_remap = mark_survivors(compute_cpe_status_remap(conn).await?);
        apply_remap(conn, "cpe_status", cpe_remap, None, &[]).await?;

        // 4. Drop the old status_id FK columns (removes FK constraints on the
        //    status table, including cpe_status's from m0002250).
        conn.execute_unprepared(
            r#"
            ALTER TABLE purl_status    DROP COLUMN IF EXISTS status_id;
            ALTER TABLE product_status DROP COLUMN IF EXISTS status_id;
            ALTER TABLE cpe_status     DROP COLUMN IF EXISTS status_id;
            "#,
        )
        .await?;

        // 5. Drop the old status table (now safe: no FK references remain). Must
        //    precede type creation — the name collides in pg_type.
        conn.execute_unprepared("DROP TABLE IF EXISTS status CASCADE;")
            .await?;

        // 6. Create the PostgreSQL enum type 'status' (idempotent). The variants
        //    come from the shared `status_enum_variants()` list that the drift
        //    test also checks against the entity.
        create_enum_if_not_exists(manager, StatusEnum::Table, status_enum_variants()).await?;

        // 7. Add the enum columns and cast the migrated text data.
        conn.execute_unprepared(
            r#"
            ALTER TABLE purl_status    ADD COLUMN IF NOT EXISTS status status;
            ALTER TABLE product_status ADD COLUMN IF NOT EXISTS status status;
            ALTER TABLE cpe_status     ADD COLUMN IF NOT EXISTS status status;

            UPDATE purl_status    SET status = status_text::status;
            UPDATE product_status SET status = status_text::status;
            UPDATE cpe_status     SET status = status_text::status;

            ALTER TABLE purl_status    ALTER COLUMN status SET NOT NULL;
            ALTER TABLE product_status ALTER COLUMN status SET NOT NULL;
            ALTER TABLE cpe_status     ALTER COLUMN status SET NOT NULL;

            ALTER TABLE purl_status    DROP COLUMN IF EXISTS status_text;
            ALTER TABLE product_status DROP COLUMN IF EXISTS status_text;
            ALTER TABLE cpe_status     DROP COLUMN IF EXISTS status_text;
            "#,
        )
        .await?;

        // 8. Recreate the composite read-path indexes that referenced status_id
        //    (auto-dropped with the column in step 4) on the new enum column,
        //    preserving their original column order.
        conn.execute_unprepared(
            r#"
            CREATE INDEX IF NOT EXISTS package_status_idx
                ON purl_status USING btree (base_purl_id, advisory_id, status);
            CREATE INDEX IF NOT EXISTS purl_status_combo_idx
                ON purl_status USING btree (base_purl_id, advisory_id, vulnerability_id, status, context_cpe_id);
            CREATE INDEX IF NOT EXISTS product_status_idx
                ON product_status USING btree (context_cpe_id, status, package, vulnerability_id);
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Note: the in-place PK recompute done by up() is NOT reversed. A
        // faithful inverse is impossible (the duplicate-`fixed` collapse is
        // lossy), and it is unnecessary — the recomputed ids remain internally
        // consistent with their remediation children. down() only restores the
        // schema shape so the migration is reversible for CI refresh.

        // 0. Save enum values to temporary text columns before dropping the enum.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status    ADD COLUMN IF NOT EXISTS status_text text;
                ALTER TABLE product_status ADD COLUMN IF NOT EXISTS status_text text;
                ALTER TABLE cpe_status     ADD COLUMN IF NOT EXISTS status_text text;
                UPDATE purl_status    SET status_text = status::text;
                UPDATE product_status SET status_text = status::text;
                UPDATE cpe_status     SET status_text = status::text;
                "#,
            )
            .await?;

        // 1. Drop enum columns and enum type — the enum type occupies the
        //    "status" name in pg_type, which would conflict with the implicit
        //    composite type created by the table in the next step.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status    DROP COLUMN IF EXISTS status;
                ALTER TABLE product_status DROP COLUMN IF EXISTS status;
                ALTER TABLE cpe_status     DROP COLUMN IF EXISTS status;
                DROP TYPE IF EXISTS status;
                "#,
            )
            .await?;

        // 2. Recreate the status table and seed data.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TABLE IF NOT EXISTS status (
                    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
                    slug character varying NOT NULL,
                    name character varying NOT NULL,
                    description character varying
                );

                INSERT INTO status (id, slug, name, description) VALUES
                    ('85b912db-fc1b-4e75-8b27-68b68c0ed828', 'affected', 'Affected', 'Vulnerabililty affects'),
                    ('619aba21-abba-4220-9e3e-110cf87e5393', 'not_affected', 'Not Affected', 'Vulnerabililty does not affect'),
                    ('c0273e43-2b0c-4dae-a3b3-c4f9733fbfa7', 'fixed', 'Fixed', 'Vulnerabililty is fixed'),
                    ('23613500-86a4-4cdb-bc92-8c74e18764da', 'under_investigation', 'Under Investigation', 'Vulnerabililty is under investigation'),
                    ('2bb0325b-0948-44ea-bab7-46af9fc834eb', 'fixed', 'Fixed', 'Vulnerabililty is fixed'),
                    ('858a3f17-d864-4be8-932e-4a634de47b8b', 'recommended', 'Recommended', 'Vulnerabililty is fixed & recommended')
                ON CONFLICT DO NOTHING;
                "#,
            )
            .await?;

        // 3. Add status_id columns, populate from saved text via slug lookup,
        //    re-add FKs, and recreate the status_id composite indexes.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status    ADD COLUMN IF NOT EXISTS status_id uuid;
                ALTER TABLE product_status ADD COLUMN IF NOT EXISTS status_id uuid;
                ALTER TABLE cpe_status     ADD COLUMN IF NOT EXISTS status_id uuid;

                UPDATE purl_status    SET status_id = s.id FROM status s WHERE s.slug = purl_status.status_text;
                UPDATE product_status SET status_id = s.id FROM status s WHERE s.slug = product_status.status_text;
                UPDATE cpe_status     SET status_id = s.id FROM status s WHERE s.slug = cpe_status.status_text;

                ALTER TABLE purl_status    ALTER COLUMN status_id SET NOT NULL;
                ALTER TABLE product_status ALTER COLUMN status_id SET NOT NULL;
                ALTER TABLE cpe_status     ALTER COLUMN status_id SET NOT NULL;

                ALTER TABLE purl_status
                    ADD CONSTRAINT package_status_status_id_fkey
                    FOREIGN KEY (status_id) REFERENCES status(id);
                ALTER TABLE product_status
                    ADD CONSTRAINT product_status_status_id_fkey
                    FOREIGN KEY (status_id) REFERENCES status(id);
                ALTER TABLE cpe_status
                    ADD CONSTRAINT cpe_status_status_id_fkey
                    FOREIGN KEY (status_id) REFERENCES status(id);

                ALTER TABLE purl_status    DROP COLUMN IF EXISTS status_text;
                ALTER TABLE product_status DROP COLUMN IF EXISTS status_text;
                ALTER TABLE cpe_status     DROP COLUMN IF EXISTS status_text;

                CREATE INDEX IF NOT EXISTS package_status_idx
                    ON purl_status USING btree (base_purl_id, advisory_id, status_id);
                CREATE INDEX IF NOT EXISTS purl_status_combo_idx
                    ON purl_status USING btree (base_purl_id, advisory_id, vulnerability_id, status_id, context_cpe_id);
                CREATE INDEX IF NOT EXISTS product_status_idx
                    ON product_status USING btree (context_cpe_id, status_id, package, vulnerability_id);
                "#,
            )
            .await?;

        Ok(())
    }
}

/// Marks, for each recomputed `new_id`, exactly one surviving `old_id` (the
/// smallest, for determinism). The rest are duplicates that collapse onto the
/// survivor — the duplicate-`fixed` seed (two `status` rows share the `fixed`
/// slug) is the only source of these collisions.
fn mark_survivors(pairs: Vec<(Uuid, Uuid)>) -> Vec<(Uuid, Uuid, bool)> {
    let mut survivor: HashMap<Uuid, Uuid> = HashMap::with_capacity(pairs.len());
    for (old_id, new_id) in &pairs {
        survivor
            .entry(*new_id)
            .and_modify(|s| {
                if old_id < s {
                    *s = *old_id;
                }
            })
            .or_insert(*old_id);
    }
    pairs
        .into_iter()
        .map(|(old_id, new_id)| {
            let is_survivor = survivor[&new_id] == old_id;
            (old_id, new_id, is_survivor)
        })
        .collect()
}

async fn compute_purl_status_remap<C: ConnectionTrait>(
    conn: &C,
) -> Result<Vec<(Uuid, Uuid)>, DbErr> {
    let rows = conn
        .query_all(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT id, status_text, base_purl_id, version_range_id, advisory_id, \
             vulnerability_id, context_cpe_id FROM purl_status",
        ))
        .await?;
    let mut remap = Vec::with_capacity(rows.len());
    for row in rows {
        let old_id: Uuid = row.try_get("", "id")?;
        let status: String = row.try_get("", "status_text")?;
        let base_purl_id: Uuid = row.try_get("", "base_purl_id")?;
        let version_range_id: Uuid = row.try_get("", "version_range_id")?;
        let advisory_id: Uuid = row.try_get("", "advisory_id")?;
        let vulnerability_id: String = row.try_get("", "vulnerability_id")?;
        let context_cpe_id: Option<Uuid> = row.try_get("", "context_cpe_id")?;
        let new_id = purl_status_id(
            &status,
            base_purl_id,
            version_range_id,
            advisory_id,
            &vulnerability_id,
            context_cpe_id,
        );
        remap.push((old_id, new_id));
    }
    Ok(remap)
}

async fn compute_product_status_remap<C: ConnectionTrait>(
    conn: &C,
) -> Result<Vec<(Uuid, Uuid)>, DbErr> {
    let rows = conn
        .query_all(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT id, status_text, product_version_range_id, advisory_id, \
             vulnerability_id, context_cpe_id, package FROM product_status",
        ))
        .await?;
    let mut remap = Vec::with_capacity(rows.len());
    for row in rows {
        let old_id: Uuid = row.try_get("", "id")?;
        let status: String = row.try_get("", "status_text")?;
        let product_version_range_id: Uuid = row.try_get("", "product_version_range_id")?;
        let advisory_id: Uuid = row.try_get("", "advisory_id")?;
        let vulnerability_id: String = row.try_get("", "vulnerability_id")?;
        let context_cpe_id: Option<Uuid> = row.try_get("", "context_cpe_id")?;
        let package: Option<String> = row.try_get("", "package")?;
        let new_id = product_status_id(
            &status,
            product_version_range_id,
            advisory_id,
            &vulnerability_id,
            context_cpe_id,
            package.as_deref(),
        );
        remap.push((old_id, new_id));
    }
    Ok(remap)
}

async fn compute_cpe_status_remap<C: ConnectionTrait>(
    conn: &C,
) -> Result<Vec<(Uuid, Uuid)>, DbErr> {
    let rows = conn
        .query_all(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT id, status_text, cpe_id, version_range_id, advisory_id, \
             vulnerability_id, context_cpe_id FROM cpe_status",
        ))
        .await?;
    let mut remap = Vec::with_capacity(rows.len());
    for row in rows {
        let old_id: Uuid = row.try_get("", "id")?;
        let status: String = row.try_get("", "status_text")?;
        let cpe_id: Uuid = row.try_get("", "cpe_id")?;
        let version_range_id: Uuid = row.try_get("", "version_range_id")?;
        let advisory_id: Uuid = row.try_get("", "advisory_id")?;
        let vulnerability_id: String = row.try_get("", "vulnerability_id")?;
        let context_cpe_id: Option<Uuid> = row.try_get("", "context_cpe_id")?;
        let new_id = cpe_status_id(
            &status,
            cpe_id,
            version_range_id,
            advisory_id,
            &vulnerability_id,
            context_cpe_id,
        );
        remap.push((old_id, new_id));
    }
    Ok(remap)
}

/// Applies an `(old_id, new_id, survivor)` remap to a status table's `id` PK,
/// deleting collapsed duplicates and cascading to an optional remediation child.
///
/// The recomputed ids form a namespace disjoint from the old ids, and survivors
/// carry distinct new ids, so each rewrite below is safe as a single statement
/// even though the PK/FK constraints are non-deferrable.
///
/// `merge_array_cols` names array columns that are *not* part of the id hash, so
/// colliding rows may legitimately hold different values in them; those are
/// unioned into the survivor before the losers are deleted (otherwise the loser's
/// values would vanish with it). Only `product_status.csaf_product_ids` needs
/// this today; `purl_status`/`cpe_status` pass `&[]` because every one of their
/// non-key columns is a hash input, so collapsing rows are identical elsewhere.
async fn apply_remap<C: ConnectionTrait>(
    conn: &C,
    table: &str,
    remap: Vec<(Uuid, Uuid, bool)>,
    child: Option<ChildFk>,
    merge_array_cols: &[&str],
) -> Result<(), DbErr> {
    // Stage the remap in a temp table so the parent/child rewrites can be
    // expressed as set-based SQL joins.
    conn.execute_unprepared(
        "DROP TABLE IF EXISTS _status_id_remap;
         CREATE TEMP TABLE _status_id_remap (
             old_id uuid PRIMARY KEY,
             new_id uuid NOT NULL,
             survivor boolean NOT NULL
         );",
    )
    .await?;

    // Inline the values — uuids/bools are strongly typed (not user text), so
    // this is injection-free and sidesteps the bind-parameter ceiling.
    for chunk in remap.chunks(1000) {
        let mut sql =
            String::from("INSERT INTO _status_id_remap (old_id, new_id, survivor) VALUES ");
        for (i, (old_id, new_id, survivor)) in chunk.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("('{old_id}','{new_id}',{survivor})"));
        }
        sql.push(';');
        conn.execute_unprepared(&sql).await?;
    }

    // Preserve non-hashed array columns across the collapse: for each set of
    // rows colliding onto one survivor, replace the survivor's value with the
    // sorted DISTINCT union of every colliding row's values, so nothing the
    // loser held is dropped when it is deleted below. Restricted to genuine
    // collisions (`HAVING count(*) > 1`), and to groups where some row actually
    // has values (`unnest` yields no rows for NULL/empty), so non-colliding
    // survivors and all-empty groups are left byte-for-byte untouched.
    for col in merge_array_cols {
        conn.execute_unprepared(&format!(
            r#"
            WITH collisions AS (
                SELECT new_id FROM _status_id_remap
                GROUP BY new_id HAVING count(*) > 1
            ),
            merged AS (
                SELECT m.new_id, array_agg(DISTINCT elem ORDER BY elem) AS vals
                FROM _status_id_remap m
                JOIN collisions c ON c.new_id = m.new_id
                JOIN {table} p ON p.id = m.old_id
                CROSS JOIN LATERAL unnest(p.{col}) AS elem
                GROUP BY m.new_id
            )
            UPDATE {table} p
            SET {col} = merged.vals
            FROM _status_id_remap m
            JOIN merged ON merged.new_id = m.new_id
            WHERE p.id = m.old_id AND m.survivor;
            "#,
            table = table,
            col = col,
        ))
        .await?;
    }

    if let Some(child) = &child {
        // The FK blocks repointing children while the parent still holds old
        // ids, so drop it (SeaORM auto-generated its name — look it up) and
        // re-add it once both sides are rewritten.
        conn.execute_unprepared(&format!(
            r#"
            DO $$
            DECLARE r record;
            BEGIN
                FOR r IN
                    SELECT conname FROM pg_constraint
                    WHERE conrelid = '{child}'::regclass
                      AND confrelid = '{parent}'::regclass
                      AND contype = 'f'
                LOOP
                    EXECUTE format('ALTER TABLE {child} DROP CONSTRAINT %I', r.conname);
                END LOOP;
            END$$;
            "#,
            child = child.table,
            parent = table,
        ))
        .await?;

        // When duplicate-`fixed` parents collapse onto one survivor id, several
        // children of the same owner would land on the same (owner, new_id)
        // composite PK. Keep one (smallest old fk value), delete the rest.
        conn.execute_unprepared(&format!(
            r#"
            DELETE FROM {child} c
            USING _status_id_remap m
            WHERE c.{fk} = m.old_id
              AND EXISTS (
                  SELECT 1
                  FROM {child} c2
                  JOIN _status_id_remap m2 ON c2.{fk} = m2.old_id
                  WHERE c2.{owner} = c.{owner}
                    AND m2.new_id = m.new_id
                    AND m2.old_id < m.old_id
              );
            "#,
            child = child.table,
            fk = child.fk_col,
            owner = child.owner_col,
        ))
        .await?;

        // Repoint the survivors onto the recomputed parent ids.
        conn.execute_unprepared(&format!(
            "UPDATE {child} c SET {fk} = m.new_id
             FROM _status_id_remap m WHERE c.{fk} = m.old_id;",
            child = child.table,
            fk = child.fk_col,
        ))
        .await?;
    }

    // Drop the collapsed duplicate parents, then move survivors to their new
    // ids. Children (if any) already point at the survivor's new id.
    conn.execute_unprepared(&format!(
        "DELETE FROM {table} p USING _status_id_remap m
         WHERE p.id = m.old_id AND NOT m.survivor;"
    ))
    .await?;
    conn.execute_unprepared(&format!(
        "UPDATE {table} p SET id = m.new_id
         FROM _status_id_remap m WHERE p.id = m.old_id AND m.survivor;"
    ))
    .await?;

    if let Some(child) = &child {
        // Re-add the FK, now also cascading updates so any future id recompute
        // needs no manual drop/re-add dance.
        conn.execute_unprepared(&format!(
            "ALTER TABLE {child}
                ADD CONSTRAINT {name}
                FOREIGN KEY ({fk}) REFERENCES {parent}(id)
                ON DELETE CASCADE ON UPDATE CASCADE;",
            child = child.table,
            name = child.new_fk_name,
            fk = child.fk_col,
            parent = table,
        ))
        .await?;
    }

    conn.execute_unprepared("DROP TABLE IF EXISTS _status_id_remap;")
        .await?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::{mark_survivors, status_enum_variants};
    use uuid::Uuid;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn survivors_no_collision() {
        // Distinct recomputed ids: every row survives untouched.
        let marked = mark_survivors(vec![(u(1), u(10)), (u(2), u(20)), (u(3), u(30))]);
        assert!(marked.iter().all(|(_, _, survivor)| *survivor));
    }

    #[test]
    fn survivors_collision_keeps_smallest_old_id() {
        // old ids u(2) and u(5) both recompute to u(99) — the duplicate-`fixed`
        // collapse. The smaller old id survives; the other is a loser.
        let mut marked = mark_survivors(vec![(u(5), u(99)), (u(2), u(99)), (u(7), u(50))]);
        marked.sort();
        assert_eq!(
            marked,
            vec![
                (u(2), u(99), true),
                (u(5), u(99), false),
                (u(7), u(50), true),
            ]
        );
    }

    /// Guards the Postgres enum this migration creates against drift from
    /// `entity::status::Status`. The checked labels come from
    /// `status_enum_variants()` — the *same* list `up()` feeds to
    /// `create_enum_if_not_exists` — so this genuinely tests the type that gets
    /// built, not a third hand-copied array.
    ///
    /// A mismatch is a real bug: the created enum and the entity's `Status`
    /// (which SeaORM serializes when *ingesting after* this migration) would
    /// disagree, so a value the entity emits but the type lacks would be rejected
    /// on insert. This turns that latent runtime break into a unit-test failure.
    #[test]
    fn status_enum_matches_entity_variants() {
        use sea_orm::{ActiveEnum, Iterable};
        use sea_orm_migration::prelude::IntoIden;
        use trustify_entity::status::Status;

        // Rendered from the single source `up()` builds the enum from, via the
        // same `into_iden().to_string()` path `create_enum_if_not_exists` uses to
        // emit each label (e.g. "not_affected").
        let mut migration_labels: Vec<String> = status_enum_variants()
            .into_iter()
            .map(|variant| variant.into_iden().to_string())
            .collect();
        migration_labels.sort();

        // Compare against the value SeaORM actually writes to the enum column —
        // `to_value()` yields the `#[sea_orm(string_value = ...)]`, i.e. what an
        // insert emits after this migration. Using that (rather than strum's
        // `Display`) makes this test self-contained instead of silently relying
        // on entity::status::Status's separate strum/serde alignment test.
        let mut entity_slugs: Vec<String> = Status::iter().map(|s| s.to_value()).collect();
        entity_slugs.sort();

        // Sorted-vector equality (not contains + count) so a duplicated label on
        // either side can't mask a genuinely missing variant.
        assert_eq!(
            migration_labels, entity_slugs,
            "the Postgres `status` enum this migration creates and \
             entity::status::Status disagree; if you changed a Status variant, \
             update StatusEnum and status_enum_variants() to match (and vice versa)"
        );
    }
}
