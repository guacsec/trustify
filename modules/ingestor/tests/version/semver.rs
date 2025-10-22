use crate::version::common::{Version, VersionRange, version_matches};
use sea_orm::{ConnectionTrait, Statement};
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_test_context::TrustifyContext;

#[path = "common.rs"]
mod common;

async fn semver_cmp(db: &Database, left: &str, right: &str) -> Result<Option<i32>, anyhow::Error> {
    let result = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM semver_cmp( '{left}', '{right}' )
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

async fn semver_precedence(db: &Database, versions: Vec<&str>) -> Result<(), anyhow::Error> {
    for (left, right) in versions.iter().zip(versions[1..].iter()) {
        let result = semver_cmp(db, left, right).await?;
        assert_eq!(result, Some(-1));
    }
    Ok(())
}

async fn semver_reverse_precedence(
    db: &Database,
    versions: Vec<&str>,
) -> Result<(), anyhow::Error> {
    for (left, right) in versions.iter().zip(versions[1..].iter()) {
        let result = semver_cmp(db, left, right).await?;
        assert_eq!(result, Some(1));
    }
    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn version_compare(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    semver_precedence(
        db,
        vec![
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.2",
            "1.1.3",
        ],
    )
    .await?;

    semver_reverse_precedence(
        db,
        vec![
            "1.1.3",
            "1.0.2",
            "1.0.0",
            "1.0.0-rc.1",
            "1.0.0-beta.11",
            "1.0.0-beta.2",
            "1.0.0-beta",
            "1.0.0-alpha.beta",
            "1.0.0-alpha.1",
            "1.0.0-alpha",
        ],
    )
    .await?;

    Ok(())
}

async fn semver_fn(
    db: &Database,
    left: &str,
    func: &str,
    right: &str,
) -> Result<Option<bool>, anyhow::Error> {
    let result = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM semver_{func}( '{left}', '{right}' )
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

async fn semver_eq(db: &Database, left: &str, right: &str) -> Result<Option<bool>, anyhow::Error> {
    semver_fn(db, left, "eq", right).await
}

async fn semver_gt(db: &Database, left: &str, right: &str) -> Result<Option<bool>, anyhow::Error> {
    semver_fn(db, left, "gt", right).await
}

async fn semver_gte(db: &Database, left: &str, right: &str) -> Result<Option<bool>, anyhow::Error> {
    semver_fn(db, left, "gte", right).await
}

async fn semver_lte(db: &Database, left: &str, right: &str) -> Result<Option<bool>, anyhow::Error> {
    semver_fn(db, left, "lte", right).await
}

async fn semver_lt(db: &Database, left: &str, right: &str) -> Result<Option<bool>, anyhow::Error> {
    semver_fn(db, left, "lt", right).await
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn comparison_helpers(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert_eq!(Some(true), semver_eq(db, "1.0.0", "1.0.0").await?);
    assert_eq!(Some(false), semver_eq(db, "1.0.1", "1.0.0").await?);

    assert_eq!(Some(true), semver_lte(db, "1.0.0", "1.0.0").await?);
    assert_eq!(Some(true), semver_lte(db, "1.0.0", "1.0.1").await?);
    assert_eq!(Some(false), semver_lte(db, "1.0.1", "1.0.0").await?);

    assert_eq!(Some(false), semver_lt(db, "1.0.0", "1.0.0").await?);
    assert_eq!(Some(true), semver_lt(db, "1.1.1", "1.2.0").await?);

    assert_eq!(Some(false), semver_gt(db, "1.0.0", "1.0.0").await?);
    assert_eq!(Some(true), semver_gt(db, "1.2.1", "1.2.0").await?);

    assert_eq!(Some(false), semver_gte(db, "1.0.0", "1.0.1").await?);
    assert_eq!(Some(true), semver_gte(db, "1.0.0", "1.0.0").await?);
    assert_eq!(Some(true), semver_gte(db, "1.2.1", "1.2.0").await?);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(version_matches(db, "1.0.2", VersionRange::Exact("1.0.2"), "semver").await?);
    assert!(!version_matches(db, "1.0.2", VersionRange::Exact("1.0.0"), "semver").await?);

    assert!(
        version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Unbounded, Version::Inclusive("1.0.2")),
            "semver"
        )
        .await?
    );

    assert!(
        !version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Unbounded, Version::Exclusive("1.0.2")),
            "semver"
        )
        .await?
    );

    assert!(
        version_matches(
            db,
            "1.0.2-beta.2",
            VersionRange::Range(Version::Unbounded, Version::Exclusive("1.0.2")),
            "semver"
        )
        .await?
    );

    assert!(
        version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Inclusive("1.0.2"), Version::Exclusive("1.0.5")),
            "semver"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_version_matches_datelike(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    assert!(
        version_matches(
            &ctx.db,
            "7.1.0-0.20231218164901.0660a66.el9",
            VersionRange::Range(
                Version::Inclusive("7.1.0-0.20231218164901.0660a66.el9"),
                Version::Exclusive("8.1.0-0.20231218164901.0660a66.el9"),
            ),
            "semver"
        )
        .await?
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_version_matches_shalike(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    assert!(
        !version_matches(
            &ctx.db,
            "sha256:cab90a3a2eb5bdff7a1420a6d89c64a8d32b1be7bd3ec311e483d2c3b9a47307",
            VersionRange::Range(
                Version::Inclusive("7.1.0-0.20231218164901.0660a66.el9"),
                Version::Exclusive("8.1.0-0.20231218164901.0660a66.el9"),
            ),
            "semver"
        )
        .await?
    );

    Ok(())
}
