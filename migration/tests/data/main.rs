#![recursion_limit = "512"]

mod m0002010;
mod m0002280;
mod m0002710;
mod parallel;

use migration::{
    Migrator, MigratorExt, MigratorTraitSelf,
    data::{Migrations, Options},
};
use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::MigrationTrait;
use std::collections::BTreeSet;
use test_context::test_context;
use test_log::test;
use trustify_module_storage::service::dispatch::DispatchBackend;
use trustify_test_context::TrustifyMigrationContext;

struct MigratorTest {
    storage: DispatchBackend,
    options: Options,
}

impl MigratorTest {
    fn new(storage: impl Into<DispatchBackend>, options: impl Into<Options>) -> Self {
        Self {
            storage: storage.into(),
            options: options.into(),
        }
    }
}

mod sbom {
    use futures_util::FutureExt;
    use migration::{
        ColumnDef, DeriveIden, DeriveMigrationName, Table, async_trait,
        data::{
            MigrationTraitWithData, SchemaDataManager,
            sbom::{self, Sbom as SbomDoc},
        },
    };
    use sea_orm::{ConnectionTrait, DbErr, Statement};
    use trustify_module_ingestor::service::DetectedDocument;

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
                .process(self, |sbom: SbomDoc, id: sbom::Id, tx| {
                    async move {
                        // we just pick a random value
                        let value = match sbom.0 {
                            DetectedDocument::CycloneDx(sbom) => sbom.serial_number,
                            DetectedDocument::Spdx(sbom) => Some(
                                sbom.sbom
                                    .document_creation_information
                                    .spdx_document_namespace,
                            ),
                            _ => None,
                        };

                        if let Some(value) = value {
                            let stmt = Statement::from_sql_and_values(
                                tx.get_database_backend(),
                                r#"UPDATE SBOM SET FOO = $1 WHERE SBOM_ID = $2"#,
                                [value.into(), id.sbom.into()],
                            );
                            tx.execute_raw(stmt).await?;
                        }

                        Ok(())
                    }
                    .boxed()
                })
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

#[sea_orm_migration::async_trait::async_trait]
impl MigratorTraitSelf for MigratorTest {
    fn migrations(&self) -> Vec<Box<dyn MigrationTrait>> {
        Self::build_migrations().into_migration_vec(self.storage.clone(), self.options.clone())
    }
}

/// test an example migration base on an existing database dump from the previous commit.
///
/// The idea is to add a new field and populate it with data.
///
/// As we don't actually change the entities, this has to work with plain SQL.
#[test_context(TrustifyMigrationContext)]
#[test(tokio::test)]
async fn examples(ctx: &TrustifyMigrationContext) -> Result<(), anyhow::Error> {
    let migrator = MigratorTest::new(ctx.storage.clone(), ());
    migrator.up(&ctx.db, None).await?;

    let result = ctx
        .db
        .query_all_raw(Statement::from_string(
            ctx.db.get_database_backend(),
            r#"SELECT FOO FROM SBOM"#,
        ))
        .await?;

    let foos = result
        .into_iter()
        .map(|row| row.try_get_by(0))
        .collect::<Result<BTreeSet<String>, _>>()?;

    assert_eq!(
        // including those which only parse with invalid license expressions replaced
        [
            "https://access.redhat.com/security/data/sbom/beta/spdx/quarkus-bom-d6ecbbd9-31bf-46fd-afda-8082120f5260",
            "https://access.redhat.com/security/data/sbom/beta/spdx/ubi8-container-1e7fb966-cc2a-41e2-8e9d-ab6fb97d67d6",
            "https://access.redhat.com/security/data/sbom/beta/spdx/ubi8-micro-container-0ca57f3b-b0e7-4251-b32b-d2929a52f05c",
            "https://access.redhat.com/security/data/sbom/beta/spdx/ubi8-minimal-container-5b43ae22-cbf0-4626-8ec5-4ae0765a3d4b",
            "https://access.redhat.com/security/data/sbom/beta/spdx/ubi9-container-f8098ef8-eee0-4ee6-b5d1-b00d992adef5",
            "https://access.redhat.com/security/data/sbom/beta/spdx/ubi9-minimal-container-9b954617-943f-43ab-bd5b-3df62a706ed6"
        ].into_iter().map(|s| s.to_owned()).collect::<BTreeSet<_>>(),
        foos
    );

    Ok(())
}
