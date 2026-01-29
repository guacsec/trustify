use clap::Parser;

use crate::commands::Commands;
use crate::config::Config;

/// Trustify CLI - Software Supply-Chain Security tool
#[derive(Parser)]
#[command(name = "trustify")]
#[command(about = "CLI for interacting with the Trustify API", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(flatten)]
    pub config: Config,

    #[command(subcommand)]
    pub command: Commands,
}
