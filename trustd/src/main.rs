#![recursion_limit = "512"]

use clap::Parser;
use std::{
    env,
    process::{ExitCode, Termination},
};
use tokio::{
    select,
    task::{LocalSet, spawn_local},
};

mod db;
mod openapi;

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Run the API server
    Api(trustify_server::profile::api::Run),
    /// Run the importer server
    Importer(trustify_server::profile::importer::Run),
    /// Manage the database
    Db(db::Run),
    /// Access OpenAPI related information of the API server
    Openapi(openapi::Run),
}

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "trustd",
    long_about = None
)]
pub struct Trustd {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

impl Trustd {
    async fn run(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Some(Command::Api(run)) => run.run().await,
            Some(Command::Importer(run)) => run.run().await,
            Some(Command::Db(run)) => run.run().await,
            Some(Command::Openapi(run)) => run.run().await,
            None => pm_mode().await,
        }
    }
}

// Project Manager Mode
async fn pm_mode() -> anyhow::Result<ExitCode> {
    let Some(Command::Db(mut db)) = Trustd::parse_from(["trustd", "db", "migrate"]).command else {
        unreachable!()
    };

    let postgres = db.start().await?;

    if !postgres.database_exists(&db.database.name).await? {
        db.command = db::Command::Create;
    }
    db.run().await?;

    let api = Trustd::parse_from([
        "trustd",
        "api",
        #[cfg(feature = "garage-door")]
        "--embedded-oidc",
        "--sample-data",
        "--db-port",
        &postgres.settings().port.to_string(),
    ]);

    let importer = Trustd::parse_from([
        "trustd",
        "importer",
        "--working-dir",
        ".trustify/importer",
        "--db-port",
        &postgres.settings().port.to_string(),
    ]);

    LocalSet::new()
        .run_until(async {
            select! {
                ret = spawn_local(api.run())=> { ret },
                ret = spawn_local(importer.run())=> { ret },
            }
        })
        .await?
}

#[tokio::main]
async fn main() -> impl Termination {
    match Trustd::parse().run().await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("Error: {err}");
            for (n, err) in err.chain().skip(1).enumerate() {
                if n == 0 {
                    eprintln!("Caused by:");
                }
                eprintln!("\t{err}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Trustd::command().debug_assert();
    }

    #[cfg(test)]
    mod test {
        use crate::{Command, Trustd};
        use clap::Parser;
        use temp_env::with_vars;

        /// test splitting the client ids via comma
        // We can only test this here as here we have the Trustd struct that clap can parse.
        #[test]
        fn test_multi_client_ids_env() {
            let result = with_vars(
                [("AUTHENTICATOR_OIDC_CLIENT_IDS", Some("frontend,walker"))],
                || Trustd::try_parse_from(["trustd", "api"]),
            );

            let Ok(Trustd {
                command: Some(Command::Api(run)),
                ..
            }) = result
            else {
                panic!("must parse into the api command");
            };

            assert_eq!(run.auth.clients.client_ids, vec!["frontend", "walker"])
        }
    }
}
