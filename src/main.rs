mod api;
mod auth;
mod cli;
mod commands;
mod config;

use std::process;

use clap::Parser;

use api::client::AuthCredentials;
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

    // Build auth credentials and get initial token if configured
    let (token, auth_credentials) =
        if let Some((sso_url, client_id, client_secret)) = cli.config.auth_credentials() {
            let token_url = if sso_url.ends_with("/token") {
                sso_url.to_string()
            } else if sso_url.ends_with('/') {
                format!("{}protocol/openid-connect/token", sso_url)
            } else {
                format!("{}/protocol/openid-connect/token", sso_url)
            };

            // Store credentials for token refresh
            let creds = AuthCredentials {
                token_url: token_url.clone(),
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
            };

            match auth::get_token(&token_url, client_id, client_secret).await {
                Ok(token) => (Some(token), Some(creds)),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        } else {
            (None, None)
        };

    // Create API client with auth credentials for token refresh
    let client = ApiClient::new(&cli.config.url, token, auth_credentials);

    let ctx = Context {
        config: cli.config,
        client,
    };

    cli.command.run(&ctx).await;
}
