use clap::Subcommand;
use std::process::ExitCode;

use crate::Context;
use crate::api::auth::AuthCredentials;

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Get authentication token
    Token {},
}

impl AuthCommands {
    pub async fn run(&self, ctx: &Context) -> anyhow::Result<ExitCode> {
        match self {
            AuthCommands::Token {} => match ctx.config.auth_credentials() {
                Some((token_url, client_id, client_secret)) => {
                    let creds = AuthCredentials::new(token_url, client_id, client_secret);
                    let token = creds.get_token().await?;
                    println!("{}", token);
                    Ok(ExitCode::SUCCESS)
                }
                None => {
                    eprintln!("Error: SSO URL, client ID, and client secret are all required");
                    Err(anyhow::anyhow!("Missing authentication credentials"))
                }
            },
        }
    }
}
