mod common;
mod mavenver;
mod pythonver;
mod rpmver;
mod semver;

use crate::version::common::{Version, VersionRange, version_matches};
use rstest::rstest;
use test_context::AsyncTestContext;
use trustify_entity::version_scheme::VersionScheme;
use trustify_test_context::TrustifyContext;

#[rstest]
#[case("1", VersionRange::Exact("1"), VersionScheme::Generic, true)]
#[case("1.0", VersionRange::Exact("1"), VersionScheme::Generic, false)]
#[case("1.0.0", VersionRange::Exact("1.0.0"), VersionScheme::Semver, true)]
#[case("1.0.1", VersionRange::Exact("1.0.0"), VersionScheme::Semver, false)]
#[case("1.0.1", VersionRange::range("1".."2"), VersionScheme::Semver, true)]
#[case("1.0.1", VersionRange::range("1".."1.2"), VersionScheme::Semver, true)]
#[case("1.0.1", VersionRange::range("1".."1.0.2"), VersionScheme::Semver, true)]
// A fully-unbounded range (no low and no high bound) means "all versions
// affected" (e.g. a version-less CSAF known_affected) and must match every
// version, across all schemes (TC-5732). Before the fix these returned false.
#[case(
    "1.2.3-1.el8",
    VersionRange::Range(Version::Unbounded, Version::Unbounded),
    VersionScheme::Rpm,
    true
)]
#[case(
    "115.15.0",
    VersionRange::Range(Version::Unbounded, Version::Unbounded),
    VersionScheme::Semver,
    true
)]
#[case(
    "1.0.0",
    VersionRange::Range(Version::Unbounded, Version::Unbounded),
    VersionScheme::Generic,
    true
)]
#[case(
    "1.0.0",
    VersionRange::Range(Version::Unbounded, Version::Unbounded),
    VersionScheme::Maven,
    true
)]
#[case(
    "1.0.0",
    VersionRange::Range(Version::Unbounded, Version::Unbounded),
    VersionScheme::Python,
    true
)]
#[test_log::test(tokio::test)]
async fn versions(
    #[case] candidate: &str,
    #[case] range: VersionRange,
    #[case] version_scheme: VersionScheme,
    #[case] expected: bool,
) -> anyhow::Result<()> {
    let ctx = TrustifyContext::setup().await;

    let actual = version_matches(&ctx.db, candidate, range, version_scheme).await?;
    assert_eq!(actual, expected);

    Ok(())
}
