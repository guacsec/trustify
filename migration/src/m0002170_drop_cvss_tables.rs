use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP FUNCTION IF EXISTS public.cvss3_ui_score(public.cvss3_ui);
                DROP FUNCTION IF EXISTS public.cvss3_severity(double precision);
                DROP FUNCTION IF EXISTS public.cvss3_score(public.cvss3);
                DROP FUNCTION IF EXISTS public.cvss3_scope_changed(public.cvss3_s);
                DROP FUNCTION IF EXISTS public.cvss3_pr_scoped_score(public.cvss3_pr, boolean);
                DROP FUNCTION IF EXISTS public.cvss3_impact(public.cvss3);
                DROP FUNCTION IF EXISTS public.cvss3_i_score(public.cvss3_i);
                DROP FUNCTION IF EXISTS public.cvss3_exploitability(public.cvss3);
                DROP FUNCTION IF EXISTS public.cvss3_c_score(public.cvss3_c);
                DROP FUNCTION IF EXISTS public.cvss3_av_score(public.cvss3_av);
                DROP FUNCTION IF EXISTS public.cvss3_ac_score(public.cvss3_ac);
                DROP FUNCTION IF EXISTS public.cvss3_a_score(public.cvss3_a);
                "#,
            )
            .await?;

        manager
            .drop_table(Table::drop().table(Cvss3::Table).if_exists().to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Cvss4::Table).if_exists().to_owned())
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE vulnerability
                    ALTER COLUMN base_severity TYPE severity USING base_severity::text::severity,
                    ADD COLUMN IF NOT EXISTS base_type score_type;

                UPDATE vulnerability SET base_type = '3.0' WHERE base_severity IS NOT NULL;

                ALTER TABLE vulnerability
                    ADD CONSTRAINT base_score_consistency CHECK (
                        (base_score IS NULL AND base_severity IS NULL AND base_type IS NULL)
                        OR
                        (base_score IS NOT NULL AND base_severity IS NOT NULL AND base_type IS NOT NULL)
                    );

                DROP TYPE IF EXISTS cvss3_a;
                DROP TYPE IF EXISTS cvss3_ac;
                DROP TYPE IF EXISTS cvss3_av;
                DROP TYPE IF EXISTS cvss3_c;
                DROP TYPE IF EXISTS cvss3_i;
                DROP TYPE IF EXISTS cvss3_pr;
                DROP TYPE IF EXISTS cvss3_s;
                DROP TYPE IF EXISTS cvss3_severity;
                DROP TYPE IF EXISTS cvss3_ui;
                DROP TYPE IF EXISTS cvss4_ac;
                DROP TYPE IF EXISTS cvss4_at;
                DROP TYPE IF EXISTS cvss4_av;
                DROP TYPE IF EXISTS cvss4_pr;
                DROP TYPE IF EXISTS cvss4_sa;
                DROP TYPE IF EXISTS cvss4_sc;
                DROP TYPE IF EXISTS cvss4_si;
                DROP TYPE IF EXISTS cvss4_ui;
                DROP TYPE IF EXISTS cvss4_va;
                DROP TYPE IF EXISTS cvss4_vc;
                DROP TYPE IF EXISTS cvss4_vi;
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Cvss3::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Cvss3::AdvisoryId)
                            .uuid()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::VulnerabilityId)
                            .string()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::MinorVersion)
                            .integer()
                            .not_null()
                            .to_owned(),
                    )
                    .primary_key(
                        Index::create()
                            .col(Cvss3::AdvisoryId)
                            .col(Cvss3::VulnerabilityId)
                            .col(Cvss3::MinorVersion),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("cvss3_advisory_id_fkey")
                            .from(Cvss3::Table, Cvss3::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Cvss4::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Cvss4::AdvisoryId)
                            .uuid()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::VulnerabilityId)
                            .string()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::MinorVersion)
                            .integer()
                            .not_null()
                            .to_owned(),
                    )
                    .primary_key(
                        Index::create()
                            .col(Cvss4::AdvisoryId)
                            .col(Cvss4::VulnerabilityId)
                            .col(Cvss4::MinorVersion),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("cvss4_advisory_id_fkey")
                            .from(Cvss4::Table, Cvss4::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002170_drop_cvss_tables/down.sql"))
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Advisory {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Cvss3 {
    Table,
    AdvisoryId,
    VulnerabilityId,
    MinorVersion,
}

#[derive(DeriveIden)]
enum Cvss4 {
    Table,
    AdvisoryId,
    VulnerabilityId,
    MinorVersion,
}
