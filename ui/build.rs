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
    use std::{
        env,
        error::Error,
        fs, io,
        path::{Path, PathBuf},
        process::Command,
    };

    /// Points to a pre-built Trunk distribution, which skips Node and Trunk entirely.
    const DIST: &str = "TRUSTIFY_UI_DIST";

    pub fn build() -> Result<(), Box<dyn Error>> {
        let output = PathBuf::from(env::var("OUT_DIR")?);
        println!("cargo:rerun-if-env-changed={DIST}");
        let dist = match env::var_os(DIST).filter(|dist| !dist.is_empty()) {
            Some(dist) => {
                let dist = PathBuf::from(dist);
                if !dist.is_absolute() {
                    return Err(io::Error::other(format!(
                        "{DIST} must be an absolute path, got {}",
                        dist.display()
                    ))
                    .into());
                }
                println!("cargo:rerun-if-changed={}", dist.display());
                dist
            }
            None => trunk(&output)?,
        };

        // The same compiled assets support either mount without a second Wasm build.
        let index = fs::read_to_string(dist.join("index.html")).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot read {}: {error}", dist.join("index.html").display()),
            )
        })?;
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

    /// Builds the console with Trunk from a staged copy of its web inputs in `OUT_DIR`.
    ///
    /// The npm install lives next to the staged inputs, so Cargo never writes to the source
    /// tree and does not race with `trunk serve` or builds in other target directories.
    fn trunk(output: &Path) -> Result<PathBuf, Box<dyn Error>> {
        let source = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
        let web = output.join("web");
        let dist = output.join("dist");
        for input in [
            "src",
            "assets",
            "scripts",
            "index.html",
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

        stage(&source, &web)?;

        let status = Command::new("node")
            .arg(source.join("scripts/install-dependencies.mjs"))
            .arg(&web)
            .args(["--omit=dev", "--prefer-offline", "--no-audit", "--no-fund"])
            .status()
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("cannot run Node.js: {error}; install Node.js and npm"),
                )
            })?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "console dependency install failed ({status}); see npm output above"
            ))
            .into());
        }

        let mut command = Command::new("trunk");
        command
            .current_dir(&web)
            .arg("build")
            .arg("--config")
            .arg(web.join("Trunk.toml"))
            .args([
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
                "cannot run Trunk: {error}; install trunk 0.22.1, Node.js/npm, and the wasm32-unknown-unknown Rust target, or set {DIST}"
            ))
        })?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "console build failed ({status}); see Trunk output above"
            ))
            .into());
        }
        Ok(dist)
    }

    /// Copies the web inputs Trunk reads relative to `index.html` into `web`.
    ///
    /// `node_modules` is kept between runs; the install script skips unchanged installs.
    fn stage(source: &Path, web: &Path) -> io::Result<()> {
        fs::create_dir_all(web)?;
        // Assets removed from the sources must not linger in the build.
        let assets = web.join("assets");
        if assets.exists() {
            fs::remove_dir_all(&assets)?;
        }
        copy_dir(&source.join("assets"), &assets)?;
        for file in ["package.json", "package-lock.json"] {
            fs::copy(source.join(file), web.join(file))?;
        }

        // Trunk still compiles the crate in place, inside the workspace. It resolves every
        // href against the HTML file, even absolute ones, so the link must be relative.
        let index = fs::read_to_string(source.join("index.html"))?;
        let manifest = "href=\"Cargo.toml\"";
        if !index.contains(manifest) {
            return Err(io::Error::other(format!(
                "index.html is missing the Rust link ({manifest})"
            )));
        }
        let relative = relative(web, &source.join("Cargo.toml"))?;
        fs::write(
            web.join("index.html"),
            index.replace(
                manifest,
                &format!("href=\"{}\"", relative.to_string_lossy().replace('\\', "/")),
            ),
        )?;
        // The build passes all options itself and must not run the development hooks.
        fs::write(web.join("Trunk.toml"), "[build]\ntarget = \"index.html\"\n")
    }

    /// Returns `target` relative to the directory `base`; both must be absolute.
    fn relative(base: &Path, target: &Path) -> io::Result<PathBuf> {
        let base = base.components().collect::<Vec<_>>();
        let target = target.components().collect::<Vec<_>>();
        let common = base
            .iter()
            .zip(&target)
            .take_while(|(base, target)| base == target)
            .count();
        if common == 0 {
            return Err(io::Error::other(
                "the Cargo output and source directories share no common root",
            ));
        }
        let mut path = PathBuf::new();
        for _ in common..base.len() {
            path.push("..");
        }
        path.extend(&target[common..]);
        Ok(path)
    }

    fn copy_dir(source: &Path, target: &Path) -> io::Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let path = target.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_dir(&entry.path(), &path)?;
            } else {
                fs::copy(entry.path(), path)?;
            }
        }
        Ok(())
    }
}
