#![allow(clippy::unwrap_used)]
#![recursion_limit = "512"]

use crate::log::init_log;
use clap::{Parser, Subcommand};

mod dataset;
mod log;
mod openapi;
mod precommit;
mod schema;

#[derive(Debug, Parser)]
pub struct Xtask {
    #[command(subcommand)]
    command: Command,
}

impl Xtask {
    pub async fn run(self) -> anyhow::Result<()> {
        match self.command {
            Command::Openapi(command) => command.run().await,
            Command::GenerateDump(command) => command.run().await,
            Command::GenerateSchemas(command) => command.run(),
            Command::Precommit(command) => command.run().await,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Used to generate and/or validate the openapi spec
    Openapi(openapi::Openapi),
    /// Generate a sample data database dump
    GenerateDump(dataset::GenerateDump),
    /// Generate all schemas
    GenerateSchemas(schema::GenerateSchema),
    /// Run precommit checks
    Precommit(precommit::Precommit),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_log()?;
    Xtask::parse().run().await
}
