use crate::cataloger::{Cataloger, DiscoveredPackage, read_file_limited};
use crate::error::Error;
use std::path::{Path, PathBuf};

/// Discovers Rust crates from `Cargo.lock` files.
pub struct CargoCataloger;

impl Cataloger for CargoCataloger {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn globs(&self) -> &[&str] {
        &["Cargo.lock"]
    }

    fn catalog(&self, _root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error> {
        let mut packages = Vec::new();

        for path in matched {
            let content = read_file_limited(path)?;
            parse_cargo_lock(&content, path, &mut packages);
        }

        Ok(packages)
    }
}

/// Parse a `Cargo.lock` file and extract packages.
///
/// The format is TOML with `[[package]]` entries containing `name` and
/// `version` fields.
fn parse_cargo_lock(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    // Simple line-oriented parser: Cargo.lock has a well-defined structure
    // of `[[package]]` blocks with `name = "..."` and `version = "..."`.
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            // Emit previous package if complete.
            emit_cargo_package(&current_name, &current_version, path, packages);
            current_name = None;
            current_version = None;
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("name = ") {
            current_name = Some(unquote_toml(val));
        } else if let Some(val) = trimmed.strip_prefix("version = ") {
            current_version = Some(unquote_toml(val));
        }
    }

    // Emit last package.
    emit_cargo_package(&current_name, &current_version, path, packages);
}

fn emit_cargo_package(
    name: &Option<String>,
    version: &Option<String>,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) {
    if let (Some(name), Some(version)) = (name, version) {
        packages.push(DiscoveredPackage {
            purl: format!("pkg:cargo/{name}@{version}"),
            name: name.clone(),
            version: version.clone(),
            source: "cargo",
            locations: vec![path.to_path_buf()],
        });
    }
}

/// Remove surrounding double quotes from a TOML string value.
fn unquote_toml(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_cargo_lock_basic() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.183"

[[package]]
name = "tokio"
version = "1.52.0"
"#;
        let path = Path::new("Cargo.lock");
        let mut packages = Vec::new();
        parse_cargo_lock(content, path, &mut packages);

        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].purl, "pkg:cargo/serde@1.0.183");
        assert_eq!(packages[1].purl, "pkg:cargo/tokio@1.52.0");
    }

    #[test]
    fn parse_cargo_lock_empty() {
        let content = "# empty lockfile\n";
        let path = Path::new("Cargo.lock");
        let mut packages = Vec::new();
        parse_cargo_lock(content, path, &mut packages);
        assert!(packages.is_empty());
    }
}
