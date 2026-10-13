mod common;
mod mavenver;
mod pythonver;
mod rpmver;
mod semver;

use crate::version::common::{VersionRange, version_matches};
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
// CVE wildcards (e.g. Linux kernel records): `*` is no upper bound, `5.4.*` the 5.4 branch
#[case("7.0.0", VersionRange::range("6.5.0".."*"), VersionScheme::Semver, true)]
#[case("6.4.0", VersionRange::range("6.5.0".."*"), VersionScheme::Semver, false)]
#[case("5.4.280", VersionRange::range("5.4.269"..="5.4.*"), VersionScheme::Semver, true)]
#[case("5.4.269", VersionRange::range("5.4.269"..="5.4.*"), VersionScheme::Semver, true)]
#[case("5.4.268", VersionRange::range("5.4.269"..="5.4.*"), VersionScheme::Semver, false)]
#[case("5.5.0", VersionRange::range("5.4.269"..="5.4.*"), VersionScheme::Semver, false)]
#[case("5.40.0", VersionRange::range("5.4.269"..="5.4.*"), VersionScheme::Semver, false)]
#[case("1.2-3.el9", VersionRange::range("1.0"..="1.*"), VersionScheme::Rpm, true)]
#[case("2.0-1.el9", VersionRange::range("1.0"..="1.*"), VersionScheme::Rpm, false)]
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
