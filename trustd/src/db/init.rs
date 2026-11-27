use anyhow::{Context, ensure};
use hide::Hide;
use sea_orm::{
    ConnectionTrait, DbBackend, EntityTrait, Set, SqlxPostgresConnector, Statement, TransactionTrait,
    sea_query::{OnConflict, PostgresQueryBuilder, QueryBuilder, QuotedBuilder},
};
use serde_json::Value;
use sqlx::{AssertSqlSafe, ConnectOptions, Connection, postgres::PgPoolOptions, raw_sql};
use std::{collections::BTreeMap, path::PathBuf, process::ExitCode};
use time::OffsetDateTime;
use trustify_common::{config::Database, db};
use trustify_entity::importer;
use uuid::Uuid;

/// Administrative connection settings come from the usual TRUSTD_DB_* variables.
#[derive(clap::Args, Debug, Clone)]
pub struct Provision {
    /// Application database to create if missing
    #[arg(long, env = "TRUSTD_DB_PROVISION_NAME")]
    name: String,
    /// Application login role to create if missing
    #[arg(long, env = "TRUSTD_DB_PROVISION_USER")]
    user: String,
    /// Application role password (updated on every run)
    #[arg(long, env = "TRUSTD_DB_PROVISION_PASSWORD", hide_env_values = true)]
    password: Hide<String>,
}

impl Provision {
    pub async fn run(self, database: Database) -> anyhow::Result<ExitCode> {
        // PostgreSQL identifiers are limited to 63 bytes; reject truncation and NULs.
        for name in [&self.name, &self.user] {
            ensure!(
                !name.is_empty() && name.len() <= 63 && !name.contains('\0'),
                "database and role names must contain 1–63 bytes and no NUL"
            );
        }
        ensure!(
            !self.password.0.contains('\0'),
            "password must not contain NUL"
        );
        let db = db::connect_admin(&database).await?;
        let builder = PostgresQueryBuilder;
        let mut name = String::new();
        let mut user = String::new();
        builder.prepare_iden(&self.name.clone().into(), &mut name);
        builder.prepare_iden(&self.user.clone().into(), &mut user);

        // CREATE DATABASE cannot run inside a transaction.
        if !exists(
            &db,
            "SELECT 1 FROM pg_database WHERE datname = $1",
            &self.name,
        )
        .await?
        {
            db.execute_unprepared(&format!("CREATE DATABASE {name}"))
                .await?;
        }
        if !exists(&db, "SELECT 1 FROM pg_roles WHERE rolname = $1", &self.user).await? {
            db.execute_unprepared(&format!("CREATE ROLE {user} LOGIN"))
                .await?;
        }
        // Utility statements cannot bind parameters. Bypass ORM query tracing and
        // disable driver statement logging for the statement containing the password.
        let options = db.get_postgres_connection_pool().connect_options();
        let mut connection = options
            .as_ref()
            .clone()
            .disable_statement_logging()
            .connect()
            .await?;
        // SeaQuery quotes both the role identifier and password literal.
        raw_sql(AssertSqlSafe(format!(
            "ALTER ROLE {user} PASSWORD {}",
            builder.value_to_string(&self.password.0.into())
        )))
        .execute(&mut connection)
        .await?;
        connection.close().await?;
        db.execute_unprepared(&format!("GRANT CONNECT ON DATABASE {name} TO {user}"))
            .await?;
        db.close().await?;

        // Reuse the actual connection options (including URL/TLS/IAM settings).
        // Set the target name structurally so URI-special characters stay literal.
        let db = SqlxPostgresConnector::from_sqlx_postgres_pool(
            PgPoolOptions::new()
                .max_connections(1)
                .connect_with(options.as_ref().clone().database(&self.name))
                .await?,
        );
        let tx = db.begin().await?;
        for sql in [
            format!("GRANT USAGE ON SCHEMA public TO {user}"),
            format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {user}"
            ),
            format!(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {user}"
            ),
        ] {
            tx.execute_unprepared(&sql).await?;
        }
        tx.commit().await?;
        db.close().await?;
        Ok(ExitCode::SUCCESS)
    }
}

async fn exists(db: &impl ConnectionTrait, sql: &str, name: &str) -> anyhow::Result<bool> {
    Ok(db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            [name.into()],
        ))
        .await?
        .is_some())
}

#[derive(clap::Args, Debug, Clone)]
pub struct Importers {
    /// JSON object mapping importer names to configurations
    #[arg(long)]
    file: PathBuf,
}

impl Importers {
    pub async fn run(self, database: Database) -> anyhow::Result<ExitCode> {
        let content = tokio::fs::read(&self.file)
            .await
            .context("read importer configurations")?;
        let importers: BTreeMap<String, Value> = serde_json::from_slice(&content)
            .context("expected a JSON object mapping importer names to configurations")?;
        let db = db::Database::new(&database).await?;
        upsert_importers(&db, importers).await?;
        db.close().await?;
        Ok(ExitCode::SUCCESS)
    }
}

async fn upsert_importers(
    db: &db::Database,
    importers: BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    let tx = db.begin().await?;
    for (name, configuration) in importers {
        importer::Entity::insert(importer::ActiveModel {
            name: Set(name),
            revision: Set(Uuid::new_v4()),
            state: Set(importer::State::Waiting),
            last_change: Set(OffsetDateTime::now_utc()),
            configuration: Set(configuration),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::column(importer::Column::Name)
                .update_columns([importer::Column::Revision, importer::Column::Configuration])
                .to_owned(),
        )
        .exec(&tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Trustd;
    use clap::Parser;
    use postgresql_embedded::PostgreSQL;
    use serde_json::json;

    #[tokio::test]
    async fn provision_and_importers_are_repeatable() -> anyhow::Result<()> {
        let mut postgres = PostgreSQL::new(trustify_db::embedded::default_settings()?);
        postgres.setup().await?;
        postgres.start().await?;
        let admin = Database {
            name: "postgres".into(),
            ..Database::from_port(postgres.settings().port)?
        };
        let provision = Provision {
            name: "provision_test".into(),
            user: "application\"role".into(),
            password: "password'with\\quotes".to_string().into(),
        };
        provision.clone().run(admin.clone()).await?;
        let target = Database {
            name: provision.name.clone(),
            ..admin.clone()
        };
        let db = db::Database::new(&target).await?;
        db.execute_unprepared(
            "CREATE TABLE existing (value text); INSERT INTO existing VALUES ('keep')",
        )
        .await?;
        provision.clone().run(admin).await?;
        assert!(
            db.query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT * FROM existing"
            ))
            .await?
            .is_some()
        );
        db.execute_unprepared("CREATE TABLE future (value text)")
            .await?;
        for table in ["existing", "future"] {
            let row = db
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT has_table_privilege($1, $2, 'SELECT,INSERT,UPDATE,DELETE') AS allowed",
                    [provision.user.clone().into(), table.into()],
                ))
                .await?
                .unwrap();
            assert!(row.try_get::<bool>("", "allowed")?);
        }

        // Only the columns used by this command are needed for this integration test.
        db.execute_unprepared(
            "CREATE TABLE importer (
            name text PRIMARY KEY, revision uuid NOT NULL, state integer NOT NULL,
            last_change timestamptz NOT NULL, configuration jsonb NOT NULL)",
        )
        .await?;
        let directory = tempfile::tempdir()?;
        let file = directory.path().join("importers.json");
        let name = "vendor's importer";
        let first = json!({name: {"description": "vendor's feed", "disabled": false}});
        tokio::fs::write(&file, serde_json::to_vec(&first)?).await?;
        Importers { file: file.clone() }.run(target.clone()).await?;
        let original = db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT revision::text, configuration FROM importer",
            ))
            .await?
            .unwrap();
        assert_eq!(original.try_get::<Value>("", "configuration")?, first[name]);
        // Existing runtime state must survive a configuration update.
        db.execute_unprepared("UPDATE importer SET state = 1")
            .await?;
        let updated = json!({name: {"description": "updated", "disabled": true}});
        tokio::fs::write(&file, serde_json::to_vec(&updated)?).await?;
        Importers { file: file.clone() }.run(target.clone()).await?;
        let row = db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT name, revision::text, state, configuration FROM importer",
            ))
            .await?
            .unwrap();
        assert_eq!(row.try_get::<String>("", "name")?, name);
        assert_eq!(row.try_get::<Value>("", "configuration")?, updated[name]);
        assert_eq!(row.try_get::<i32>("", "state")?, 1);
        assert_ne!(
            row.try_get::<String>("", "revision")?,
            original.try_get::<String>("", "revision")?
        );
        tokio::fs::write(&file, b"{}").await?;
        Importers { file: file.clone() }.run(target.clone()).await?;
        tokio::fs::write(&file, b"[]").await?;
        assert!(Importers { file }.run(target).await.is_err());
        db.close().await?;
        postgres.stop().await?;
        Ok(())
    }

    #[test]
    fn initialization_cli_and_password_redaction() {
        let cli = Trustd::try_parse_from([
            "trustd",
            "db",
            "--db-name",
            "postgres",
            "provision",
            "--name",
            "application",
            "--user",
            "app",
            "--password",
            "app-password-should-never-appear-9876",
        ])
        .unwrap();
        assert!(!format!("{cli:?}").contains("app-password-should-never-appear-9876"));
        assert!(
            Trustd::try_parse_from(["trustd", "db", "importers", "--file", "importers.json"])
                .is_ok()
        );
    }
}
