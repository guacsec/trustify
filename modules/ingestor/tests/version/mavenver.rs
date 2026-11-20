use crate::version::common::{Version, VersionRange, version_matches};
use sea_orm::{ConnectionTrait, Statement};
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_test_context::TrustifyContext;

#[path = "common.rs"]
mod common;

async fn mavenver_cmp(
    db: &Database,
    left: &str,
    right: &str,
) -> Result<Option<i32>, anyhow::Error> {
    let result = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM mavenver_cmp( '{left}', '{right}' )
        "#,
            ),
        ))
        .await?;

    if let Some(result) = result {
        Ok(result.try_get_by_index(0)?)
    } else {
        Ok(None)
    }
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_mavenver_cmp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8.3", "2.9.0").await?);

    assert_eq!(Some(0), mavenver_cmp(&ctx.db, "1.8.3", "1.8.3").await?);

    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8.3", "1.8.2").await?);

    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8.3", "1.8").await?);
    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8", "1.8.3").await?);
    assert_eq!(Some(0), mavenver_cmp(&ctx.db, "1.8", "1.8.0").await?);

    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "1.8-beta3", "1.8-beta4").await?
    );
    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "1.8-beta-3", "1.8-beta-4").await?
    );
    assert_eq!(
        Some(1),
        mavenver_cmp(&ctx.db, "1.8-beta4", "1.8-beta3").await?
    );
    assert_eq!(
        Some(1),
        mavenver_cmp(&ctx.db, "1.8-beta-4", "1.8-beta-3").await?
    );

    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8-beta3", "1.8").await?);
    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8", "1.8-beta-3").await?);

    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8-1", "1.8-3").await?);
    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8-3", "1.8-1").await?);

    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8-1", "1.8.0-3").await?);
    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8-3", "1.8.0-1").await?);

    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "4.1.108.Final", "4.1.108.Final-redhat-0001").await?
    );
    assert_eq!(
        Some(-1),
        mavenver_cmp(
            &ctx.db,
            "4.1.108.Alpha-redhat-0001",
            "4.1.108.Final-redhat-0001"
        )
        .await?
    );
    assert_eq!(
        Some(0),
        mavenver_cmp(
            &ctx.db,
            "4.1.108.Final-redhat-0001",
            "4.1.108.Final-redhat-0001"
        )
        .await?
    );
    assert_eq!(
        Some(-1),
        mavenver_cmp(
            &ctx.db,
            "4.1.108.Final-redhat-0001",
            "4.1.108.Final-redhat-0002"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(version_matches(db, "1.0.2", VersionRange::Exact("1.0.2"), "maven").await?);
    assert!(!version_matches(db, "1.0.2", VersionRange::Exact("1.0.0"), "maven").await?);

    assert!(
        version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Unbounded, Version::Inclusive("1.0.2")),
            "maven"
        )
        .await?
    );

    assert!(
        !version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Unbounded, Version::Exclusive("1.0.2")),
            "maven"
        )
        .await?
    );

    assert!(
        version_matches(
            db,
            "1.0.2-beta.2",
            VersionRange::Range(Version::Unbounded, Version::Exclusive("1.0.2")),
            "maven"
        )
        .await?
    );

    assert!(
        version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Inclusive("1.0.2"), Version::Exclusive("1.0.5")),
            "maven"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches_commons_compress(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(
        !version_matches(
            db,
            "1.26",
            VersionRange::Range(Version::Inclusive("1.21"), Version::Exclusive("1.26")),
            "maven"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches_commons_compress_but_as_semver_because_the_cve_says_its_semver(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(
        !version_matches(
            db,
            "1.26",
            VersionRange::Range(Version::Inclusive("1.21"), Version::Exclusive("1.26")),
            "semver"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches_rht_suffixen(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(
        !version_matches(
            db,
            "1.26.0.redhat-00001",
            VersionRange::Range(Version::Inclusive("1.21"), Version::Exclusive("1.26")),
            "maven"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches_rht_suffixen_as_semver_wrongly(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(
        !version_matches(
            db,
            "1.26.0.redhat-00001",
            VersionRange::Range(Version::Inclusive("1.21"), Version::Exclusive("1.26")),
            "semver"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches_netty_codec(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(
        version_matches(
            db,
            "4.1.108.Final-redhat-0001",
            VersionRange::Exact("4.1.108.Final-redhat-0001"),
            "maven"
        )
        .await?
    );

    assert!(
        version_matches(
            db,
            "4.1.108.Final-redhat-0001",
            VersionRange::Range(Version::Inclusive("4.1.108"), Version::Exclusive("4.2")),
            "maven"
        )
        .await?
    );

    assert!(
        !version_matches(
            db,
            "4.1.108.Final-redhat-0001",
            VersionRange::Range(
                Version::Inclusive("0.0"),
                Version::Exclusive("4.1.108.Final")
            ),
            "maven"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches_netty_codec_semver(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(
        version_matches(
            db,
            "4.1.108.Final-redhat-0001",
            VersionRange::Exact("4.1.108.Final-redhat-0001"),
            "semver"
        )
        .await?
    );

    assert!(
        version_matches(
            db,
            "4.1.108.Final-redhat-0001",
            VersionRange::Range(Version::Inclusive("4.1.108"), Version::Exclusive("4.2")),
            "semver"
        )
        .await?
    );

    Ok(())
}

/// Verifies that a Red Hat Lightwell remediated build sorts above the backport base it annotates,
/// for every Maven suffix shape present in the `lightwell-osv` snapshot `ae0cbae`.
///
/// `rhlw` is an unknown qualifier, and Maven's ComparableVersion ranks unknown qualifiers above
/// the bare release — unlike the known qualifiers (`alpha`, `beta`, `rc`, `snapshot`), which rank
/// below it. Lightwell depends on that ordering: each advisory ends at an exclusive `fixed` bound
/// set to the remediated build, so if the build sorted *below* its base the interval would invert
/// and the advisory would silently match nothing.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_mavenver_cmp_lightwell_remediated_suffixes(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // `.rhlw-`, the dot-separated form: 239 of the 288 snapshot records.
    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "6.0.3", "6.0.3.rhlw-00001").await?
    );
    assert_eq!(
        Some(1),
        mavenver_cmp(&ctx.db, "6.0.3.rhlw-00001", "6.0.3").await?
    );

    // `-rhlw-` on a four-component base: all 31 of the snapshot's hyphenated records are
    // `.Final-rhlw-`, which keeps them on the working side of the `> 3` heuristic below.
    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "4.1.132.Final", "4.1.132.Final-rhlw-00002").await?
    );
    assert_eq!(
        Some(1),
        mavenver_cmp(&ctx.db, "4.1.132.Final-rhlw-00002", "4.1.132.Final").await?
    );

    // Successive remediations of one base are ordered by their build number.
    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "6.2.2.rhlw-00001", "6.2.2.rhlw-00004").await?
    );

    Ok(())
}

/// Guards the latent inversion in `mavenver_cmp` for a plain three-component base carrying a
/// hyphenated `rhlw` suffix (plan TC-7587 §6.2).
///
/// Maven's ComparableVersion ranks `1.2.3 < 1.2.3-rhlw-00001`, and so does `lightwell-osv`'s own
/// `tools/check_ranges.py`. `mavenver_cmp_up.sql` instead decides qualifier ordering with
/// `if array_length(left_parts,1) > 3 then return -1 else return +1`. That heuristic exists to
/// place `.Final`-style four-component builds correctly, and guesses the opposite way for a
/// three-component base, returning `+1`.
///
/// This is latent, not live: every hyphenated record in snapshot `ae0cbae` is `.Final-rhlw-`
/// (four components). It becomes a silent data-loss bug the moment Lightwell remediates a plain
/// three-component base with the hyphen form — the advisory's interval inverts and it matches
/// nothing, with no error.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[ignore = "TC-7587: mavenver_cmp inverts a hyphenated rhlw suffix on a three-component base"]
async fn test_mavenver_cmp_lightwell_hyphen_suffix_on_three_component_base(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "1.2.3", "1.2.3-rhlw-00001").await?
    );
    Ok(())
}
