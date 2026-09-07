use anyhow::{Context, anyhow};
use clap::Parser;
use std::{
    env::current_dir,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use trustify_server::openapi::create_openapi;

#[derive(Debug, Parser, Default)]
pub struct Openapi {
    /// skip generating the openapi file?
    #[arg(long, default_value = "false")]
    no_generate: bool,

    /// skip validating the openapi file??
    #[arg(long, default_value = "false")]
    no_validate: bool,
}

impl Openapi {
    pub async fn run(self) -> anyhow::Result<()> {
        if !self.no_generate {
            generate_openapi(None).await?;
        }

        if !self.no_validate {
            validate()?;
        }

        Ok(())
    }
}

fn command_exists(cmd: &str) -> bool {
    match Command::new("which").arg(cmd).output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

pub async fn generate_openapi(base: Option<&Path>) -> anyhow::Result<()> {
    let mut path = PathBuf::from("openapi.yaml");
    if let Some(base) = base {
        path = base.join(path);
    }

    // create spec from actual server

    println!("Building openapi");

    let doc = create_openapi()
        .await?
        .to_yaml()
        .context("Failed to convert openapi spec to yaml")?;

    // write

    println!("Writing openapi to {:?}", path);

    fs::write(path, doc).context("Failed to write openapi spec")?;

    Ok(())
}

pub fn validate() -> anyhow::Result<()> {
    let command = if command_exists("podman") {
        "podman"
    } else if command_exists("docker") {
        "docker"
    } else {
        return Err(anyhow!(
            "This openapi validation requires podman or docker to be installed."
        ));
    };

    println!("Validating openapi at {:?}", "openapi.yaml");

    // run the openapi validator container
    if Command::new(command)
        .args([
            "run",
            "--rm",
            "-v",
            format!("{}:/src", current_dir()?.to_str().unwrap()).as_str(),
            "--security-opt",
            "label=disable",
            "docker.io/openapitools/openapi-generator-cli:v7.7.0",
            "validate",
            "-i",
            "/src/openapi.yaml",
        ])
        .status()
        .map_err(|_| anyhow!("Failed to validate openapi.yaml"))?
        .success()
    {
        Ok(())
    } else {
        Err(anyhow!("Failed to validate openapi.yaml"))
    }
}
