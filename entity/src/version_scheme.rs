use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Copy,
    Clone,
    Eq,
    Hash,
    Debug,
    PartialEq,
    EnumIter,
    DeriveActiveEnum,
    strum::Display,
    Serialize,
    Deserialize,
)]
#[sea_orm(
    rs_type = "String",
    db_type = "String(StringLen::None)",
    rename_all = "lowercase"
)]
#[strum(serialize_all = "lowercase")]
pub enum VersionScheme {
    Generic,
    Git,
    Semver,
    Rpm,
    Python,
    Maven,
    Golang,
    Npm,
    Packagist,
    NuGet,
    Gem,
    Hex,
    Swift,
    Pub,
    Cargo,
    /// A CSAF vers-like specifier (vls): a range of versions without a versioning scheme.
    Vls,
    /// A CVE `custom` version type: the versioning scheme is unspecified.
    Custom,
}

/// Translate from other ecosystems to our internal version scheme.
///
/// For CVE see: <https://github.com/CVEProject/cve-schema/blob/6af5c9c49c5b62e7b1f46756e1f3aef328848e1c/schema/CVE_Record_Format.json#L306-L318>
///
/// However, the reality looks quite weird. The following command can be run to get an overview of
/// what the current state holds. Run from the `cves` directory of the repository from:
/// <https://github.com/CVEProject/cvelistV5>
///
/// ```bash
/// find -name "CVE-*.json" -exec jq '.containers.cna.affected?[]?.versions?[]?.versionType | select (. != null )' {} \; | sort -u
/// ```
impl From<&str> for VersionScheme {
    fn from(scheme: &str) -> Self {
        match scheme {
            "commit" | "git" => VersionScheme::Git,
            "custom" => VersionScheme::Custom,
            "maven" => VersionScheme::Maven,
            "npm" => VersionScheme::Semver,
            "python" => VersionScheme::Python,
            "rpm" => VersionScheme::Rpm,
            "semver" => VersionScheme::Semver,
            _ => VersionScheme::Generic,
        }
    }
}
