use crate::cataloger::{Cataloger, DiscoveredPackage, read_file_limited};
use crate::error::Error;
use std::path::{Path, PathBuf};

/// Discovers Alpine APK packages from the installed package database.
pub struct ApkCataloger;

impl Cataloger for ApkCataloger {
    fn name(&self) -> &'static str {
        "apk"
    }

    fn globs(&self) -> &[&str] {
        &["lib/apk/db/installed"]
    }

    fn catalog(&self, _root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error> {
        let mut packages = Vec::new();

        for path in matched {
            let content = read_file_limited(path)?;
            parse_apk_installed(&content, path, &mut packages);
        }

        Ok(packages)
    }
}

/// Parse the APK `installed` database file.
///
/// The format is record-based with blank-line separators. Each record
/// has single-letter field prefixes:
/// - `P:` package name
/// - `V:` version
/// - `o:` origin (source package name)
fn parse_apk_installed(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut origin: Option<String> = None;

    for line in content.lines() {
        if line.is_empty() {
            emit_apk_package(&name, &version, &origin, path, packages);
            name = None;
            version = None;
            origin = None;
            continue;
        }

        if let Some(val) = line.strip_prefix("P:") {
            name = Some(val.to_string());
        } else if let Some(val) = line.strip_prefix("V:") {
            version = Some(val.to_string());
        } else if let Some(val) = line.strip_prefix("o:") {
            origin = Some(val.to_string());
        }
    }

    // Emit last record if file doesn't end with a blank line.
    emit_apk_package(&name, &version, &origin, path, packages);
}

fn emit_apk_package(
    name: &Option<String>,
    version: &Option<String>,
    origin: &Option<String>,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) {
    let Some(name) = name else { return };
    let Some(version) = version else { return };

    // Use origin as the source package name when available, otherwise
    // use the package name itself.
    let source_name = origin.as_deref().unwrap_or(name);

    packages.push(DiscoveredPackage {
        purl: format!("pkg:apk/alpine/{source_name}@{version}"),
        name: name.clone(),
        version: version.clone(),
        source: "apk",
        locations: vec![path.to_path_buf()],
    });
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_apk_basic() {
        let content = "\
C:Q1abc=
P:curl
V:8.20.0-r0
A:x86_64
o:curl

C:Q2def=
P:libcurl
V:8.20.0-r0
A:x86_64
o:curl

P:musl
V:1.2.5-r0
A:x86_64

";
        let path = Path::new("lib/apk/db/installed");
        let mut packages = Vec::new();
        parse_apk_installed(content, path, &mut packages);

        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].purl, "pkg:apk/alpine/curl@8.20.0-r0");
        assert_eq!(packages[0].name, "curl");
        assert_eq!(packages[1].purl, "pkg:apk/alpine/curl@8.20.0-r0");
        assert_eq!(packages[1].name, "libcurl");
        assert_eq!(packages[2].purl, "pkg:apk/alpine/musl@1.2.5-r0");
    }

    #[test]
    fn parse_apk_empty() {
        let path = Path::new("lib/apk/db/installed");
        let mut packages = Vec::new();
        parse_apk_installed("", path, &mut packages);
        assert!(packages.is_empty());
    }
}
