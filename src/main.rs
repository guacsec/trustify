mod api;
mod auth;
mod cli;
mod commands;
mod config;

use std::process;

use clap::Parser;

use api::ApiClient;
use cli::Cli;

/// Runtime context containing config and API client
pub struct Context {
    pub config: config::Config,
    pub client: ApiClient,
}

#[tokio::main]
async fn main() {
    // Load .env file if present (silently ignore if not found)
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    // Attempt authentication if credentials are provided
    let token = if let Some((sso_url, client_id, client_secret)) = cli.config.auth_credentials() {
        let token_url = if sso_url.ends_with("/token") {
            sso_url.to_string()
        } else if sso_url.ends_with('/') {
            format!("{}protocol/openid-connect/token", sso_url)
        } else {
            format!("{}/protocol/openid-connect/token", sso_url)
        };
        match auth::get_token(&token_url, client_id, client_secret).await {
            Ok(token) => Some(token),
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
    } else {
        None
    };

    // Create API client
    let client = ApiClient::new(&cli.config.url, token);

    let ctx = Context {
        config: cli.config,
        client,
    };

    cli.command.run(&ctx).await;
}
