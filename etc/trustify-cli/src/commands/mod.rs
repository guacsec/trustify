pub mod auth;
pub mod sbom;

use clap::Subcommand;

use crate::Context;
pub use auth::AuthCommands;
pub use sbom::SbomCommands;

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
