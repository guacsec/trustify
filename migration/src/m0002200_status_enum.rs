use sea_orm_migration::prelude::*;
use sea_query::extension::postgres::Type;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // 1. Snapshot status slugs into a temp table, then drop old FK columns and status table.
        //    The table name "status" also reserves the composite type name in PostgreSQL,
        //    so it must be dropped before we can create the enum type with the same name.
        db.execute_unprepared(
            r#"CREATE TEMP TABLE _status_snapshot AS
               SELECT ps.id AS row_id, 'purl' AS kind, s.slug
               FROM purl_status ps JOIN status s ON ps.status_id = s.id
               UNION ALL
               SELECT ps.id AS row_id, 'product' AS kind, s.slug
               FROM product_status ps JOIN status s ON ps.status_id = s.id"#,
        )
        .await?;

        db.execute_unprepared(r#"ALTER TABLE "purl_status" DROP COLUMN "status_id""#)
            .await?;
        db.execute_unprepared(r#"ALTER TABLE "product_status" DROP COLUMN "status_id""#)
            .await?;
        db.execute_unprepared(r#"DROP TABLE "status""#).await?;

        // 2. Create PostgreSQL enum type
        let builder = db.get_database_backend();
        let stmt = builder
            .build(Type::create().as_enum(StatusEnum::Table).values([
                StatusEnum::Affected,
                StatusEnum::Fixed,
                StatusEnum::NotAffected,
                StatusEnum::UnderInvestigation,
                StatusEnum::Recommended,
            ]))
            .to_string();
        db.execute_unprepared(&stmt).await?;

        // 3. Add nullable enum columns
        db.execute_unprepared(r#"ALTER TABLE "purl_status" ADD COLUMN "status" "status" NULL"#)
            .await?;
        db.execute_unprepared(r#"ALTER TABLE "product_status" ADD COLUMN "status" "status" NULL"#)
            .await?;

        // 4. Populate from snapshot
        db.execute_unprepared(
            r#"UPDATE "purl_status" ps
               SET "status" = snap."slug"::status
               FROM _status_snapshot snap
               WHERE snap.row_id = ps.id AND snap.kind = 'purl'"#,
        )
        .await?;
        db.execute_unprepared(
            r#"UPDATE "product_status" ps
               SET "status" = snap."slug"::status
               FROM _status_snapshot snap
               WHERE snap.row_id = ps.id AND snap.kind = 'product'"#,
        )
        .await?;

        db.execute_unprepared(r#"DROP TABLE _status_snapshot"#)
            .await?;

        // 5. Make NOT NULL
        db.execute_unprepared(r#"ALTER TABLE "purl_status" ALTER COLUMN "status" SET NOT NULL"#)
            .await?;
        db.execute_unprepared(r#"ALTER TABLE "product_status" ALTER COLUMN "status" SET NOT NULL"#)
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // 1. Recreate the status table
        db.execute_unprepared(
            r#"CREATE TABLE "status" (
                "id" uuid PRIMARY KEY,
                "slug" text NOT NULL,
                "name" text NOT NULL,
                "description" text
            )"#,
        )
        .await?;

        // 2. Seed status rows
        db.execute_unprepared(
            r#"INSERT INTO "status" ("id", "slug", "name") VALUES
                ('7cc29b44-e708-11ed-a05b-0242ac120003', 'affected', 'Affected'),
                ('7cc29e00-e708-11ed-a05b-0242ac120003', 'not_affected', 'Not affected'),
                ('7cc29f04-e708-11ed-a05b-0242ac120003', 'fixed', 'Fixed'),
                ('7cc2a01c-e708-11ed-a05b-0242ac120003', 'under_investigation', 'Under investigation'),
                ('7cc2a0ee-e708-11ed-a05b-0242ac120003', 'recommended', 'Recommended')"#,
        )
        .await?;

        // 3. Add status_id columns back
        db.execute_unprepared(r#"ALTER TABLE "purl_status" ADD COLUMN "status_id" uuid NULL"#)
            .await?;
        db.execute_unprepared(r#"ALTER TABLE "product_status" ADD COLUMN "status_id" uuid NULL"#)
            .await?;

        // 4. Populate from enum via JOIN
        db.execute_unprepared(
            r#"UPDATE "purl_status" ps
               SET "status_id" = s."id"
               FROM "status" s
               WHERE ps."status"::text = s."slug""#,
        )
        .await?;
        db.execute_unprepared(
            r#"UPDATE "product_status" ps
               SET "status_id" = s."id"
               FROM "status" s
               WHERE ps."status"::text = s."slug""#,
        )
        .await?;

        // 5. Make NOT NULL and add FK
        db.execute_unprepared(r#"ALTER TABLE "purl_status" ALTER COLUMN "status_id" SET NOT NULL"#)
            .await?;
        db.execute_unprepared(
            r#"ALTER TABLE "product_status" ALTER COLUMN "status_id" SET NOT NULL"#,
        )
        .await?;
        db.execute_unprepared(
            r#"ALTER TABLE "purl_status" ADD CONSTRAINT "fk_purl_status_status"
               FOREIGN KEY ("status_id") REFERENCES "status"("id")"#,
        )
        .await?;
        db.execute_unprepared(
            r#"ALTER TABLE "product_status" ADD CONSTRAINT "fk_product_status_status"
               FOREIGN KEY ("status_id") REFERENCES "status"("id")"#,
        )
        .await?;

        // 6. Drop enum columns and drop enum type
        db.execute_unprepared(r#"ALTER TABLE "purl_status" DROP COLUMN "status""#)
            .await?;
        db.execute_unprepared(r#"ALTER TABLE "product_status" DROP COLUMN "status""#)
            .await?;

        manager
            .drop_type(Type::drop().if_exists().name(StatusEnum::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum StatusEnum {
    #[sea_orm(iden = "status")]
    Table,
    #[sea_orm(iden = "affected")]
    Affected,
    #[sea_orm(iden = "fixed")]
    Fixed,
    #[sea_orm(iden = "not_affected")]
    NotAffected,
    #[sea_orm(iden = "under_investigation")]
    UnderInvestigation,
    #[sea_orm(iden = "recommended")]
    Recommended,
}
