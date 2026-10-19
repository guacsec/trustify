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

/// The PURL types with a known versioning scheme, see
/// <https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst>. A vers range names its
/// scheme by the PURL type as well: "If there is a registered PURL type for a package ecosystem,
/// the PURL type will also be the name for the VERS type"
/// (<https://github.com/package-url/vers-spec/blob/main/docs/types/vers-types.md>).
#[derive(
    Copy, Clone, Eq, PartialEq, Debug, EnumIter, strum::EnumString, strum::AsRefStr, strum::Display,
)]
#[strum(serialize_all = "lowercase")]
pub enum PurlType {
    Cargo,
    Composer,
    Gem,
    Golang,
    Hex,
    Maven,
    Npm,
    Nuget,
    Pub,
    Pypi,
    Rpm,
    Swift,
}

impl From<PurlType> for VersionScheme {
    fn from(ty: PurlType) -> Self {
        match ty {
            PurlType::Cargo => Self::Cargo,
            PurlType::Composer => Self::Packagist,
            PurlType::Gem => Self::Gem,
            PurlType::Golang => Self::Golang,
            PurlType::Hex => Self::Hex,
            PurlType::Maven => Self::Maven,
            PurlType::Npm => Self::Npm,
            PurlType::Nuget => Self::NuGet,
            PurlType::Pub => Self::Pub,
            PurlType::Pypi => Self::Python,
            PurlType::Rpm => Self::Rpm,
            PurlType::Swift => Self::Swift,
        }
    }
}

/// Translate a CVE `versionType` to our internal version scheme. PURL and vers types are
/// translated through [`PurlType`].
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

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use sea_orm::Iterable;

    #[rstest]
    #[case("cargo", Some(VersionScheme::Cargo))]
    #[case("composer", Some(VersionScheme::Packagist))]
    #[case("gem", Some(VersionScheme::Gem))]
    #[case("golang", Some(VersionScheme::Golang))]
    #[case("hex", Some(VersionScheme::Hex))]
    #[case("maven", Some(VersionScheme::Maven))]
    #[case("npm", Some(VersionScheme::Npm))]
    #[case("nuget", Some(VersionScheme::NuGet))]
    #[case("pub", Some(VersionScheme::Pub))]
    #[case("pypi", Some(VersionScheme::Python))]
    #[case("rpm", Some(VersionScheme::Rpm))]
    #[case("swift", Some(VersionScheme::Swift))]
    #[case("deb", None)]
    #[case("apk", None)]
    #[case("generic", None)]
    #[case("python", None)]
    fn purl_type(#[case] ty: &str, #[case] expected: Option<VersionScheme>) {
        assert_eq!(
            ty.parse::<PurlType>().ok().map(VersionScheme::from),
            expected
        );
    }

    /// Each PURL type converts back to the name it is parsed from.
    #[test]
    fn purl_type_names() {
        for ty in PurlType::iter() {
            assert_eq!(ty.as_ref().parse::<PurlType>(), Ok(ty));
        }
    }
}
