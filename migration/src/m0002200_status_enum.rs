use sea_orm_migration::{
    prelude::{extension::postgres::Type, *},
    sea_orm::EnumIter,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Rename the status table first so its implicit composite type no longer
        // blocks creating a PostgreSQL enum type with the same name.
        let conn = manager.get_connection();

        conn.execute_unprepared(
            r#"
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM status
                    WHERE slug NOT IN ('affected', 'not_affected', 'fixed', 'under_investigation', 'recommended')
                ) THEN
                    RAISE EXCEPTION 'status table contains unexpected slug values — aborting migration';
                END IF;
            END $$;

            ALTER TABLE status RENAME TO status_old;
            ALTER INDEX status_pkey RENAME TO status_old_pkey;
            "#,
        )
        .await
        .map(|_| ())?;

        // Create the PostgreSQL enum type with the 5 status values.
        manager
            .create_type(
                Type::create()
                    .as_enum(StatusEnum::Type)
                    .values([
                        StatusEnum::Affected,
                        StatusEnum::NotAffected,
                        StatusEnum::Fixed,
                        StatusEnum::UnderInvestigation,
                        StatusEnum::Recommended,
                    ])
                    .to_owned(),
            )
            .await?;

        // Migrate data from the renamed table to new enum columns, then drop it.
        conn.execute_unprepared(
            r#"
            ALTER TABLE purl_status ADD COLUMN status status;

            UPDATE purl_status
               SET status = s.slug::status
              FROM status_old s
             WHERE purl_status.status_id = s.id;

            ALTER TABLE purl_status ALTER COLUMN status SET NOT NULL;

            ALTER TABLE purl_status DROP CONSTRAINT package_status_status_id_fkey;
            ALTER TABLE purl_status DROP COLUMN status_id;


            ALTER TABLE product_status ADD COLUMN status status;

            UPDATE product_status
               SET status = s.slug::status
              FROM status_old s
             WHERE product_status.status_id = s.id;

            ALTER TABLE product_status ALTER COLUMN status SET NOT NULL;

            ALTER TABLE product_status DROP CONSTRAINT product_status_status_id_fkey;
            ALTER TABLE product_status DROP COLUMN status_id;


            DROP TABLE status_old;
            "#,
        )
        .await
        .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // Restore status_id columns using the enum values before dropping the type.
        conn.execute_unprepared(
            r#"
            CREATE TABLE status_old (
                id uuid NOT NULL PRIMARY KEY,
                slug character varying NOT NULL,
                name character varying NOT NULL,
                description character varying
            );

            INSERT INTO status_old VALUES
                ('85b912db-fc1b-4e75-8b27-68b68c0ed828', 'affected', 'Affected', 'Vulnerabililty affects'),
                ('619aba21-abba-4220-9e3e-110cf87e5393', 'not_affected', 'Not Affected', 'Vulnerabililty does not affect'),
                ('c0273e43-2b0c-4dae-a3b3-c4f9733fbfa7', 'fixed', 'Fixed', 'Vulnerabililty is fixed'),
                ('23613500-86a4-4cdb-bc92-8c74e18764da', 'under_investigation', 'Under Investigation', 'Vulnerabililty is under investigation'),
                ('2bb0325b-0948-44ea-bab7-46af9fc834eb', 'fixed', 'Fixed', 'Vulnerabililty is fixed'),
                ('858a3f17-d864-4be8-932e-4a634de47b8b', 'recommended', 'Recommended', 'Vulnerabililty is fixed & recommended');


            ALTER TABLE purl_status ADD COLUMN status_id uuid;

            UPDATE purl_status
               SET status_id = s.id
              FROM status_old s
             WHERE purl_status.status::text = s.slug
               AND s.id = (SELECT id FROM status_old s2 WHERE s2.slug = s.slug ORDER BY id LIMIT 1);

            ALTER TABLE purl_status ALTER COLUMN status_id SET NOT NULL;
            ALTER TABLE purl_status ADD CONSTRAINT package_status_status_id_fkey
                FOREIGN KEY (status_id) REFERENCES status_old(id);
            ALTER TABLE purl_status DROP COLUMN status;


            ALTER TABLE product_status ADD COLUMN status_id uuid;

            UPDATE product_status
               SET status_id = s.id
              FROM status_old s
             WHERE product_status.status::text = s.slug
               AND s.id = (SELECT id FROM status_old s2 WHERE s2.slug = s.slug ORDER BY id LIMIT 1);

            ALTER TABLE product_status ALTER COLUMN status_id SET NOT NULL;
            ALTER TABLE product_status ADD CONSTRAINT product_status_status_id_fkey
                FOREIGN KEY (status_id) REFERENCES status_old(id);
            ALTER TABLE product_status DROP COLUMN status;
            "#,
        )
        .await
        .map(|_| ())?;

        // Drop the enum type now that no columns reference it.
        manager
            .drop_type(Type::drop().name(StatusEnum::Type).to_owned())
            .await?;

        // Rename the temporary table back to the original name.
        let conn = manager.get_connection();
        conn.execute_unprepared(
            r#"
            ALTER TABLE status_old RENAME TO status;
            ALTER INDEX status_old_pkey RENAME TO status_pkey;

            ALTER TABLE purl_status DROP CONSTRAINT package_status_status_id_fkey;
            ALTER TABLE purl_status ADD CONSTRAINT package_status_status_id_fkey
                FOREIGN KEY (status_id) REFERENCES status(id);

            ALTER TABLE product_status DROP CONSTRAINT product_status_status_id_fkey;
            ALTER TABLE product_status ADD CONSTRAINT product_status_status_id_fkey
                FOREIGN KEY (status_id) REFERENCES status(id);

            -- Recreate indexes that were dropped with the status_id columns.
            CREATE INDEX package_status_idx
                ON purl_status USING btree (base_purl_id, advisory_id, status_id);
            CREATE INDEX purl_status_combo_idx
                ON purl_status USING btree (base_purl_id, advisory_id, vulnerability_id, status_id, context_cpe_id);
            CREATE INDEX product_status_idx
                ON product_status USING btree (context_cpe_id, status_id, package, vulnerability_id);
            "#,
        )
        .await
        .map(|_| ())
    }
}

#[derive(EnumIter, strum::Display)]
#[strum(serialize_all = "snake_case")]
enum StatusEnum {
    #[strum(serialize = "status")]
    Type,
    Affected,
    NotAffected,
    Fixed,
    UnderInvestigation,
    Recommended,
}

impl Iden for StatusEnum {
    fn unquoted(&self, s: &mut dyn Write) {
        let _ = write!(s, "{}", self);
    }
}
