pub mod sbom;

use clap::Subcommand;

use crate::Context;
pub use sbom::SbomCommands;

#[derive(Subcommand)]
pub enum Commands {
    /// SBOM management commands
    Sbom {
        #[command(subcommand)]
        command: SbomCommands,
    },
}

impl Commands {
    pub async fn run(&self, ctx: &Context) {
        match self {
            Commands::Sbom { command } => command.run(ctx).await,
        }
    }
}
