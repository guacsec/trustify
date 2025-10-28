use migration::{
    Migrator, MigratorExt,
    data::{MigrationWithData, Migrations},
};
use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::{MigrationTrait, MigratorTrait};
use std::collections::BTreeSet;
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyMigrationContext;

struct MigratorTest;

mod sbom {
    use migration::{
        ColumnDef, DeriveIden, DeriveMigrationName, Table, async_trait,
        data::{MigrationTraitWithData, Sbom as SbomDoc, SchemaDataManager},
        sbom,
    };
    use sea_orm::{ConnectionTrait, DbErr, Statement};

    #[derive(DeriveMigrationName)]
    pub struct Migration;

    #[async_trait::async_trait]
    impl MigrationTraitWithData for Migration {
        async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(Sbom::Table)
                        .add_column_if_not_exists(
                            ColumnDef::new(Sbom::Foo).string().default("").to_owned(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Sbom::Table)
                        .modify_column(ColumnDef::new(Sbom::Foo).not_null().to_owned())
                        .to_owned(),
                )
                .await?;

            manager
                .process(
                    self,
                    sbom!(async |sbom, model, tx| {
                        // we just pick a random value
                        let value = match sbom {
                            SbomDoc::CycloneDx(sbom) => sbom.serial_number,
                            SbomDoc::Spdx(sbom) => {
                                Some(sbom.document_creation_information.spdx_document_namespace)
                            }
                            SbomDoc::Other(_) => None,
                        };

                        if let Some(value) = value {
                            let stmt = Statement::from_sql_and_values(
                                tx.get_database_backend(),
                                r#"UPDATE SBOM SET FOO = $1 WHERE SBOM_ID = $2"#,
                                [value.into(), model.sbom_id.into()],
                            );
                            tx.execute(stmt).await?;
                        }

                        Ok(())
                    }),
                )
                .await?;

            Ok(())
        }

        async fn down(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(Sbom::Table)
                        .drop_column(Sbom::Foo)
                        .to_owned(),
                )
                .await?;

            Ok(())
        }
    }

    #[derive(DeriveIden)]
    enum Sbom {
        Table,
        Foo,
    }
}

impl MigratorExt for MigratorTest {
    fn build_migrations() -> Migrations {
        Migrator::build_migrations().data(sbom::Migration)
    }
}

impl MigratorTrait for MigratorTest {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        Self::into_migrations()
    }
}

#[test_context(TrustifyMigrationContext)]
#[test(tokio::test)]
async fn examples(ctx: &TrustifyMigrationContext) -> Result<(), anyhow::Error> {
    MigrationWithData::run_with_test_storage(ctx.storage.clone(), async {
        MigratorTest::up(&ctx.db, None).await
    })
    .await?;

    let result = ctx
        .db
        .query_all(Statement::from_string(
            ctx.db.get_database_backend(),
            r#"SELECT FOO FROM SBOM"#,
        ))
        .await?;

    let foos = result
        .into_iter()
        .map(|row| row.try_get_by(0))
        .collect::<Result<BTreeSet<String>, _>>()?;

    assert_eq!(
        [
            "",
            "",
            "",
            "https://access.redhat.com/security/data/sbom/beta/spdx/ubi8-micro-container-0ca57f3b-b0e7-4251-b32b-d2929a52f05c",
            "https://access.redhat.com/security/data/sbom/beta/spdx/ubi9-container-f8098ef8-eee0-4ee6-b5d1-b00d992adef5",
            "https://access.redhat.com/security/data/sbom/beta/spdx/ubi9-minimal-container-9b954617-943f-43ab-bd5b-3df62a706ed6"
        ].into_iter().map(|s| s.to_owned()).collect::<BTreeSet<_>>(),
        foos
    );

    Ok(())
}
