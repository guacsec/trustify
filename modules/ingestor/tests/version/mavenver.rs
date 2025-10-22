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
        .query_one(Statement::from_string(
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
