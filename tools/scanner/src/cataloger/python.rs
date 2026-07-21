use crate::cataloger::{Cataloger, DiscoveredPackage, read_file_limited};
use crate::error::Error;
use std::path::{Path, PathBuf};

/// Discovers Python packages from dependency files and lockfiles.
pub struct PythonCataloger;

impl Cataloger for PythonCataloger {
    fn name(&self) -> &'static str {
        "python"
    }

    fn globs(&self) -> &[&str] {
        &[
            "requirements.txt",
            "Pipfile.lock",
            "poetry.lock",
            "pyproject.toml",
            "uv.lock",
        ]
    }

    fn catalog(&self, _root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error> {
        let mut packages = Vec::new();

        for path in matched {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            let content = read_file_limited(path)?;

            match filename {
                "requirements.txt" => {
                    parse_requirements_txt(&content, path, &mut packages);
                }
                "Pipfile.lock" => {
                    parse_pipfile_lock(&content, path, &mut packages)?;
                }
                "poetry.lock" => {
                    parse_poetry_lock(&content, path, &mut packages);
                }
                "pyproject.toml" => {
                    parse_pyproject_toml(&content, path, &mut packages);
                }
                "uv.lock" => {
                    parse_uv_lock(&content, path, &mut packages);
                }
                _ => {}
            }
        }

        Ok(packages)
    }
}

/// Parse `requirements.txt`: lines like `package==1.2.3` or
/// `package>=1.0,<2.0`. We only extract pinned versions (`==`).
fn parse_requirements_txt(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        // Split on `==` for pinned versions.
        if let Some((name, version)) = trimmed.split_once("==") {
            let name = name.trim();
            // Strip extras like `package[extra]==1.0`.
            let clean_name = name.split('[').next().unwrap_or(name).trim();
            let version = version.split([';', ' ', '#']).next().unwrap_or("").trim();

            if !version.is_empty() {
                let normalized = clean_name.to_lowercase().replace('_', "-");
                packages.push(DiscoveredPackage {
                    purl: format!("pkg:pypi/{normalized}@{version}"),
                    name: clean_name.to_string(),
                    version: version.to_string(),
                    source: "python-requirements",
                    locations: vec![path.to_path_buf()],
                });
            }
        }
    }
}

/// Parse `Pipfile.lock` (JSON format).
fn parse_pipfile_lock(
    content: &str,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) -> Result<(), Error> {
    let doc: serde_json::Value = serde_json::from_str(content)?;

    for section in ["default", "develop"] {
        if let Some(deps) = doc.get(section).and_then(|v| v.as_object()) {
            for (name, val) in deps {
                let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("");

                let clean_version = version.strip_prefix("==").unwrap_or(version);

                if !clean_version.is_empty() {
                    let normalized = name.to_lowercase().replace('_', "-");
                    packages.push(DiscoveredPackage {
                        purl: format!("pkg:pypi/{normalized}@{clean_version}"),
                        name: name.clone(),
                        version: clean_version.to_string(),
                        source: "python-pipfile",
                        locations: vec![path.to_path_buf()],
                    });
                }
            }
        }
    }

    Ok(())
}

/// Parse `poetry.lock` (TOML format).
///
/// Each `[[package]]` block has `name` and `version` fields.
fn parse_poetry_lock(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            emit_python_package(&current_name, &current_version, path, packages);
            current_name = None;
            current_version = None;
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("name = ") {
            current_name = Some(unquote(val));
        } else if let Some(val) = trimmed.strip_prefix("version = ") {
            current_version = Some(unquote(val));
        }
    }

    emit_python_package(&current_name, &current_version, path, packages);
}

fn emit_python_package(
    name: &Option<String>,
    version: &Option<String>,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) {
    if let (Some(name), Some(version)) = (name, version) {
        let normalized = name.to_lowercase().replace('_', "-");
        packages.push(DiscoveredPackage {
            purl: format!("pkg:pypi/{normalized}@{version}"),
            name: name.clone(),
            version: version.clone(),
            source: "python-poetry",
            locations: vec![path.to_path_buf()],
        });
    }
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

/// Parse `pyproject.toml` to extract dependencies.
///
/// Looks for `[project] dependencies = [...]` entries with pinned (`==`)
/// or minimum (`>=`) versions. Also checks `[tool.poetry.dependencies]`.
fn parse_pyproject_toml(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    // Track which section we're in.
    let mut in_dependencies = false;
    let mut in_poetry_deps = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Section headers.
        if trimmed.starts_with('[') {
            in_dependencies = trimmed == "[project]"
                || trimmed == "dependencies = ["
                || in_dependencies && trimmed.starts_with('"');
            in_poetry_deps = trimmed == "[tool.poetry.dependencies]";

            // Handle inline `dependencies = [` on the [project] line — not
            // possible, but handle the array start on a subsequent line.
            if trimmed == "[project]" {
                in_dependencies = false;
                // Will be set when we see `dependencies = [`
            }
            continue;
        }

        // Detect `dependencies = [` under [project].
        if trimmed.starts_with("dependencies") && trimmed.contains('[') {
            in_dependencies = true;
            // If the array is on the same line, check for inline entries.
            if let Some(inline) = trimmed.split('[').nth(1) {
                parse_pep508_array_line(inline, path, packages);
            }
            continue;
        }

        // End of array.
        if in_dependencies && trimmed.starts_with(']') {
            in_dependencies = false;
            continue;
        }

        // Parse PEP 508 dependency strings inside the array.
        if in_dependencies {
            parse_pep508_array_line(trimmed, path, packages);
        }

        // Parse `[tool.poetry.dependencies]` entries like:
        // package = "^1.2.3" or package = {version = "^1.2.3", ...}
        if in_poetry_deps && trimmed.contains('=') && !trimmed.starts_with('#') {
            parse_poetry_dep_line(trimmed, path, packages);
        }
    }
}

/// Parse a single line from a PEP 508 dependencies array.
///
/// Lines look like `"requests>=2.31.0",` or `"flask==3.0.0",`.
fn parse_pep508_array_line(line: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    let trimmed = line.trim().trim_matches(['"', '\'', ',', ' ']);
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(']') {
        return;
    }

    // Try pinned version first: `package==1.2.3`
    if let Some((name, version)) = trimmed.split_once("==") {
        emit_pypi_package(name, version, "python-pyproject", path, packages);
        return;
    }

    // Try minimum version: `package>=1.2.3` — use the lower bound as the
    // version since it's the best we have without a lockfile.
    if let Some((name, version)) = trimmed.split_once(">=") {
        let version = version.split([',', ';', ' ']).next().unwrap_or(version);
        emit_pypi_package(name, version, "python-pyproject", path, packages);
    }
}

/// Parse a `[tool.poetry.dependencies]` line.
///
/// Handles `name = "^1.2.3"` and `name = {version = "^1.2.3", ...}`.
fn parse_poetry_dep_line(line: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    let Some((name, rest)) = line.split_once('=') else {
        return;
    };
    let name = name.trim();
    if name == "python" {
        return;
    }

    let rest = rest.trim();

    // Simple form: name = "^1.2.3"
    if rest.starts_with('"') || rest.starts_with('\'') {
        let version = rest.trim_matches(['"', '\'', ' ']);
        let version = version.trim_start_matches(['^', '~', '>', '=', '<']);
        if !version.is_empty() {
            emit_pypi_package(name, version, "python-pyproject-poetry", path, packages);
        }
        return;
    }

    // Table form: name = {version = "^1.2.3", ...}
    if rest.starts_with('{')
        && let Some(ver_start) = rest.find("version")
    {
        let after = &rest[ver_start..];
        if let Some(eq_pos) = after.find('=') {
            let val = after[eq_pos + 1..].trim();
            let val = val.trim_start_matches([' ', '"', '\'']);
            let val = val.split(['"', '\'', ',', '}']).next().unwrap_or("");
            let version = val.trim_start_matches(['^', '~', '>', '=', '<']);
            if !version.is_empty() {
                emit_pypi_package(name, version, "python-pyproject-poetry", path, packages);
            }
        }
    }
}

/// Parse `uv.lock` to extract packages.
///
/// `uv.lock` is TOML with `[[package]]` blocks containing `name` and
/// `version` fields, similar to `poetry.lock`.
fn parse_uv_lock(content: &str, path: &Path, packages: &mut Vec<DiscoveredPackage>) {
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            emit_uv_package(&current_name, &current_version, path, packages);
            current_name = None;
            current_version = None;
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("name = ") {
            current_name = Some(unquote(val));
        } else if let Some(val) = trimmed.strip_prefix("version = ") {
            current_version = Some(unquote(val));
        }
    }

    emit_uv_package(&current_name, &current_version, path, packages);
}

fn emit_uv_package(
    name: &Option<String>,
    version: &Option<String>,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) {
    if let (Some(name), Some(version)) = (name, version) {
        let normalized = name.to_lowercase().replace('_', "-");
        packages.push(DiscoveredPackage {
            purl: format!("pkg:pypi/{normalized}@{version}"),
            name: name.clone(),
            version: version.clone(),
            source: "python-uv",
            locations: vec![path.to_path_buf()],
        });
    }
}

/// Emit a PyPI package, normalizing the name.
fn emit_pypi_package(
    name: &str,
    version: &str,
    source: &'static str,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) {
    let clean_name = name.trim().split('[').next().unwrap_or(name).trim();
    let version = version
        .trim()
        .split([';', ' ', ','])
        .next()
        .unwrap_or("")
        .trim();
    if clean_name.is_empty() || version.is_empty() {
        return;
    }
    let normalized = clean_name.to_lowercase().replace('_', "-");
    packages.push(DiscoveredPackage {
        purl: format!("pkg:pypi/{normalized}@{version}"),
        name: clean_name.to_string(),
        version: version.to_string(),
        source,
        locations: vec![path.to_path_buf()],
    });
}
