use crate::cataloger::{Cataloger, DiscoveredPackage, read_file_limited};
use crate::error::Error;
use std::path::{Path, PathBuf};

/// Discovers Debian/Ubuntu packages from the dpkg status database.
pub struct DpkgCataloger;

impl Cataloger for DpkgCataloger {
    fn name(&self) -> &'static str {
        "dpkg"
    }

    fn globs(&self) -> &[&str] {
        &["var/lib/dpkg/status"]
    }

    fn catalog(&self, _root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error> {
        let mut packages = Vec::new();

        for path in matched {
            let content = read_file_limited(path)?;
            parse_dpkg_status(&content, path, &mut packages);
        }

        Ok(packages)
    }
}

/// Parse the dpkg `status` file (RFC 822-like format).
///
/// Each record is separated by a blank line. Relevant fields:
/// - `Package:` package name
/// - `Version:` version
/// - `Source:` source package name (optional)
/// - `Status:` must contain "installed" to be counted
fn parse_dpkg_status(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut source: Option<String> = None;
    let mut installed = false;

    for line in content.lines() {
        if line.is_empty() {
            if installed {
                emit_dpkg_package(&name, &version, &source, path, packages);
            }
            name = None;
            version = None;
            source = None;
            installed = false;
            continue;
        }

        // Skip continuation lines (start with whitespace).
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }

        if let Some(val) = line.strip_prefix("Package: ") {
            name = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("Version: ") {
            version = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("Source: ") {
            // Source field may include version in parens: `source (1.0)`.
            let source_name = val.split_whitespace().next().unwrap_or(val);
            source = Some(source_name.trim().to_string());
        } else if let Some(val) = line.strip_prefix("Status: ") {
            installed = val.contains("installed") && !val.contains("not-installed");
        }
    }

    // Emit last record.
    if installed {
        emit_dpkg_package(&name, &version, &source, path, packages);
    }
}

fn emit_dpkg_package(
    name: &Option<String>,
    version: &Option<String>,
    source: &Option<String>,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) {
    let Some(name) = name else { return };
    let Some(version) = version else { return };

    let source_name = source.as_deref().unwrap_or(name);

    packages.push(DiscoveredPackage {
        purl: format!("pkg:deb/debian/{source_name}@{version}"),
        name: name.clone(),
        version: version.clone(),
        source: "dpkg",
        locations: vec![path.to_path_buf()],
    });
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_dpkg_basic() {
        let content = "\
Package: libc6
Status: install ok installed
Version: 2.36-9
Source: glibc

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: curl
Status: install ok installed
Version: 7.88.1-10+deb12u8

";
        let path = Path::new("var/lib/dpkg/status");
        let mut packages = Vec::new();
        parse_dpkg_status(content, path, &mut packages);

        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].purl, "pkg:deb/debian/glibc@2.36-9");
        assert_eq!(packages[0].name, "libc6");
        assert_eq!(packages[1].purl, "pkg:deb/debian/curl@7.88.1-10+deb12u8");
    }

    #[test]
    fn parse_dpkg_empty() {
        let path = Path::new("var/lib/dpkg/status");
        let mut packages = Vec::new();
        parse_dpkg_status("", path, &mut packages);
        assert!(packages.is_empty());
    }
}
