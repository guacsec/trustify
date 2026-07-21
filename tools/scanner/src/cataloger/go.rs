use crate::cataloger::{Cataloger, DiscoveredPackage, read_file_limited};
use crate::error::Error;
use std::path::{Path, PathBuf};

/// Discovers Go modules from `go.mod` files.
pub struct GoCataloger;

impl Cataloger for GoCataloger {
    fn name(&self) -> &'static str {
        "go"
    }

    fn globs(&self) -> &[&str] {
        &["go.sum"]
    }

    fn catalog(&self, _root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error> {
        let mut packages = Vec::new();

        for path in matched {
            let content = read_file_limited(path)?;
            parse_go_sum(&content, path, &mut packages);
        }

        Ok(packages)
    }
}

/// Parse a `go.sum` file and extract module dependencies.
///
/// Each line has format: `module version hash`
/// Versions ending in `/go.mod` are metadata entries and are skipped.
fn parse_go_sum(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let module = parts[0];
        let version = parts[1];

        // Skip `/go.mod` hash entries — they duplicate the source entry.
        if version.ends_with("/go.mod") {
            continue;
        }

        // Strip the leading `v` from the version if present.
        let clean_version = version.strip_prefix('v').unwrap_or(version);

        packages.push(DiscoveredPackage {
            purl: format!("pkg:golang/{module}@{clean_version}"),
            name: module.to_string(),
            version: clean_version.to_string(),
            source: "go",
            locations: vec![path.to_path_buf()],
        });
    }
}
