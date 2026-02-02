use clap::Subcommand;

use crate::Context;
use crate::api::auth::AuthCredentials;
use std::process;

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Get authentication token
    Token {},
}

impl AuthCommands {
    pub async fn run(&self, ctx: &Context) {
        match self {
            AuthCommands::Token {} => match ctx.config.auth_credentials() {
                Some((token_url, client_id, client_secret)) => {
                    let creds = AuthCredentials::new(token_url, client_id, client_secret);
                    match creds.get_token().await {
                        Ok(token) => println!("{}", token),
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            process::exit(1);
                        }
                    }
                }
                None => {
                    eprintln!("Error: SSO URL, client ID, and client secret are all required");
                    process::exit(1);
                }
            },
        }
    }
}
