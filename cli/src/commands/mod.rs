pub mod advisory;
pub mod auth;
pub mod sbom;

use clap::Subcommand;
use std::process::ExitCode;

use crate::Context;
pub use advisory::AdvisoryCommands;
pub use auth::AuthCommands;
pub use sbom::SbomCommands;

#[derive(Subcommand)]
pub enum Commands {
    /// SBOM management commands
    Sbom {
        #[command(subcommand)]
        command: SbomCommands,
    },

    /// Advisory management commands
    Advisory {
        #[command(subcommand)]
        command: AdvisoryCommands,
    },

    /// Authentication commands
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
}

impl Commands {
    pub async fn run(&self, ctx: &Context) -> anyhow::Result<ExitCode> {
        match self {
            Commands::Sbom { command } => command.run(ctx).await,
            Commands::Advisory { command } => command.run(ctx).await,
            Commands::Auth { command } => command.run(ctx).await,
        }
    }
}
