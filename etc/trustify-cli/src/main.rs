mod api;
mod cli;
mod commands;
mod config;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use api::{ApiClient, auth::AuthCredentials};
use cli::Cli;

/// Runtime context containing config and API client
pub struct Context {
    pub config: config::Config,
    pub client: ApiClient,
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    // Load .env file if present (silently ignore if not found)
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    // Build auth credentials and get initial token if configured
    let (token, auth_credentials) =
        if let Some((sso_url, client_id, client_secret)) = cli.config.auth_credentials() {
            let creds = AuthCredentials::new(sso_url, client_id, client_secret);
            let token = creds.get_token().await?;
            (Some(token), Some(creds))
        } else {
            (None, None)
        };

    // Create API client with auth credentials for token refresh
    let client = ApiClient::new(&cli.config.url, token, auth_credentials);

    let ctx = Context {
        config: cli.config,
        client,
    };

    cli.command.run(&ctx).await
}
