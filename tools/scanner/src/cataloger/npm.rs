use crate::cataloger::{Cataloger, DiscoveredPackage, read_file_limited};
use crate::error::Error;
use std::path::{Path, PathBuf};

/// Discovers npm packages from `package-lock.json` files.
pub struct NpmCataloger;

impl Cataloger for NpmCataloger {
    fn name(&self) -> &'static str {
        "npm"
    }

    fn globs(&self) -> &[&str] {
        &["package-lock.json"]
    }

    fn catalog(&self, _root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error> {
        let mut packages = Vec::new();

        for path in matched {
            let content = read_file_limited(path)?;
            parse_package_lock(&content, path, &mut packages)?;
        }

        Ok(packages)
    }
}

/// Parse a `package-lock.json` (v2/v3) and extract packages.
///
/// The `packages` object has keys like `"node_modules/foo"` with `version`
/// fields. The v1 format uses a `dependencies` object instead.
fn parse_package_lock(
    content: &str,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) -> Result<(), Error> {
    let doc: serde_json::Value = serde_json::from_str(content)?;

    // v2/v3: "packages" object.
    if let Some(pkgs) = doc.get("packages").and_then(|v| v.as_object()) {
        for (key, val) in pkgs {
            // Skip the root entry (empty string key).
            if key.is_empty() {
                continue;
            }

            let name = key.rsplit("node_modules/").next().unwrap_or(key);

            let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("");

            if version.is_empty() {
                continue;
            }

            // Handle scoped packages: @scope/name -> %40scope/name in PURL.
            let purl_name = if name.starts_with('@') {
                name.replacen('@', "%40", 1)
            } else {
                name.to_string()
            };

            packages.push(DiscoveredPackage {
                purl: format!("pkg:npm/{purl_name}@{version}"),
                name: name.to_string(),
                version: version.to_string(),
                source: "npm",
                locations: vec![path.to_path_buf()],
            });
        }
        return Ok(());
    }

    // v1 fallback: "dependencies" object.
    if let Some(deps) = doc.get("dependencies").and_then(|v| v.as_object()) {
        extract_npm_v1_deps(deps, path, packages);
    }

    Ok(())
}

/// Recursively extract packages from npm lockfile v1 `dependencies`.
fn extract_npm_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) {
    for (name, val) in deps {
        let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("");

        if !version.is_empty() {
            let purl_name = if name.starts_with('@') {
                name.replacen('@', "%40", 1)
            } else {
                name.clone()
            };

            packages.push(DiscoveredPackage {
                purl: format!("pkg:npm/{purl_name}@{version}"),
                name: name.clone(),
                version: version.to_string(),
                source: "npm",
                locations: vec![path.to_path_buf()],
            });
        }

        // Recurse into nested dependencies.
        if let Some(nested) = val.get("dependencies").and_then(|v| v.as_object()) {
            extract_npm_v1_deps(nested, path, packages);
        }
    }
}
