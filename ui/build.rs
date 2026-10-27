use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "embed")]
    if std::env::var("CARGO_CFG_TARGET_ARCH")? != "wasm32" {
        embedded::build()?;
    }
    Ok(())
}

#[cfg(feature = "embed")]
mod embedded {
    use static_files::resource_dir;
    use std::{env, error::Error, fs, io, path::PathBuf, process::Command};

    pub fn build() -> Result<(), Box<dyn Error>> {
        let source = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
        let output = PathBuf::from(env::var("OUT_DIR")?);
        let dist = output.join("dist");
        for input in [
            "src",
            "assets",
            "scripts",
            "index.html",
            "Trunk.toml",
            "Cargo.toml",
            "package.json",
            "package-lock.json",
            "../Cargo.toml",
            "../Cargo.lock",
            "../api",
            "../.cargo/config.toml",
        ] {
            println!("cargo:rerun-if-changed={}", source.join(input).display());
        }

        let mut command = Command::new("trunk");
        command
            .current_dir(&source)
            .args([
                "build",
                "--locked",
                "--no-default-features",
                "--features",
                "web",
                "--public-url",
                "./",
                "--dist",
            ])
            .arg(&dist);
        if env::var("PROFILE")? != "debug" {
            command.arg("--release");
        }
        // A nested Cargo build must not wait on the outer build's artifact lock,
        // inherit native compiler flags, or run through clippy-driver.
        for variable in [
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_MAKEFLAGS",
            "MAKEFLAGS",
            "MFLAGS",
            "CLIPPY_ARGS",
            "CARGO_BUILD_TARGET",
        ] {
            command.env_remove(variable);
        }
        command.env("CARGO_TARGET_DIR", output.join("wasm-target"));
        let status = command.status().map_err(|error| {
            io::Error::new(error.kind(), format!(
                "cannot run Trunk: {error}; install trunk 0.22.1, Node.js/npm, and the wasm32-unknown-unknown Rust target"
            ))
        })?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "console build failed ({status}); see Trunk output above"
            ))
            .into());
        }

        // The same compiled assets support either mount without a second Wasm build.
        let index = fs::read_to_string(dist.join("index.html"))?;
        let base = "<base href=\"./\"";
        if !index.contains(base) {
            return Err(
                io::Error::other("Trunk output is missing the relative base element").into(),
            );
        }
        for (name, path) in [
            ("index-root.html", "/"),
            ("index-console.html", "/console/"),
        ] {
            fs::write(
                output.join(name),
                index.replace(base, &format!("<base href=\"{path}\"")),
            )?;
        }
        let mut resources = resource_dir(dist);
        // Trunk leaves its lock file in dist; it is build state, not a public asset.
        resources.with_filter(|path| {
            path.file_name()
                .is_some_and(|name| !name.to_string_lossy().starts_with('.'))
        });
        resources.build()?;
        Ok(())
    }
}
