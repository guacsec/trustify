pub mod sbom;
pub mod auth;

use clap::Subcommand;

use crate::Context;
pub use sbom::SbomCommands;
pub use auth::AuthCommands;

#[derive(Subcommand)]
pub enum Commands {
    /// SBOM management commands
    Sbom {
        #[command(subcommand)]
        command: SbomCommands,
    },

    /// Authentication commands
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
}

impl Commands {
    pub async fn run(&self, ctx: &Context) {
        match self {
            Commands::Sbom { command } => command.run(ctx).await,
            Commands::Auth { command } => command.run(ctx).await,
        }
    }
}
