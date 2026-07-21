use crate::cataloger::{Cataloger, DiscoveredPackage, read_file_limited};
use crate::error::Error;
use std::path::{Path, PathBuf};

/// Discovers Maven/Gradle Java packages from `pom.xml` and
/// `gradle.lockfile` files.
pub struct MavenCataloger;

impl Cataloger for MavenCataloger {
    fn name(&self) -> &'static str {
        "maven"
    }

    fn globs(&self) -> &[&str] {
        &["gradle.lockfile"]
    }

    fn catalog(&self, _root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error> {
        let mut packages = Vec::new();

        for path in matched {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            let content = read_file_limited(path)?;

            if filename == "gradle.lockfile" {
                parse_gradle_lockfile(&content, path, &mut packages);
            }
        }

        Ok(packages)
    }
}

/// Parse a Gradle lockfile.
///
/// Each line has format: `group:artifact:version=configuration`
fn parse_gradle_lockfile(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("empty=") {
            continue;
        }

        // Split off the `=configuration` suffix.
        let gav = trimmed.split('=').next().unwrap_or(trimmed);
        let parts: Vec<&str> = gav.split(':').collect();
        if parts.len() < 3 {
            continue;
        }

        let group = parts[0];
        let artifact = parts[1];
        let version = parts[2];

        packages.push(DiscoveredPackage {
            purl: format!("pkg:maven/{group}/{artifact}@{version}"),
            name: format!("{group}:{artifact}"),
            version: version.to_string(),
            source: "gradle",
            locations: vec![path.to_path_buf()],
        });
    }
}
