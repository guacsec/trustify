use crate::version::common::{Version, VersionRange, version_matches};
use sea_orm::{ConnectionTrait, Statement};
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_test_context::TrustifyContext;

#[path = "common.rs"]
mod common;

async fn pythonver_cmp(
    db: &Database,
    left: &str,
    right: &str,
) -> Result<Option<i32>, anyhow::Error> {
    let result = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM pythonver_cmp( '{left}', '{right}' )
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
async fn test_pythonver_cmp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    assert_eq!(Some(-1), pythonver_cmp(&ctx.db, "1.8.3", "2.9.0").await?);
    assert_eq!(Some(0), pythonver_cmp(&ctx.db, "1.8.3", "1.8.3").await?);
    assert_eq!(Some(1), pythonver_cmp(&ctx.db, "1.8.3", "1.8.2").await?);

    assert_eq!(Some(1), pythonver_cmp(&ctx.db, "1.8.3", "1.8").await?);
    assert_eq!(Some(-1), pythonver_cmp(&ctx.db, "1.8", "1.8.3").await?);
    assert_eq!(Some(0), pythonver_cmp(&ctx.db, "1.8", "1.8.0").await?);

    assert_eq!(Some(-1), pythonver_cmp(&ctx.db, "1.2.3a1", "1.2.3").await?);
    assert_eq!(
        Some(-1),
        pythonver_cmp(&ctx.db, "1.2.3a1", "1.2.3.b1").await?
    );
    assert_eq!(
        Some(-1),
        pythonver_cmp(&ctx.db, "1.2.3b1", "1.2.3.rc1").await?
    );
    assert_eq!(Some(-1), pythonver_cmp(&ctx.db, "1.2.3rc1", "1.2.3").await?);
    assert_eq!(
        Some(1),
        pythonver_cmp(&ctx.db, "1.2.3.post1", "1.2.3").await?
    );
    assert_eq!(
        Some(1),
        pythonver_cmp(&ctx.db, "1.2.3.post2", "1.2.3.post1").await?
    );
    assert_eq!(
        Some(-1),
        pythonver_cmp(&ctx.db, "1.2.3.dev1", "1.2.3").await?
    );
    assert_eq!(
        Some(-1),
        pythonver_cmp(&ctx.db, "1.2.3", "1.2.3+abc").await?
    );
    assert_eq!(Some(1), pythonver_cmp(&ctx.db, "1.2.3+abc", "1.2.3").await?);
    assert_eq!(
        Some(1),
        pythonver_cmp(&ctx.db, "1.2.3+def", "1.2.3+abc").await?
    );
    assert_eq!(
        Some(-1),
        pythonver_cmp(&ctx.db, "1.2.3+abc", "1.2.3+def").await?
    );
    assert_eq!(
        Some(-1),
        pythonver_cmp(&ctx.db, "1.2.3-rc0", "1.2.3").await?
    );
    assert_eq!(Some(1), pythonver_cmp(&ctx.db, "1.2.3", "1.2.3-rc0").await?);
    assert_eq!(
        Some(0),
        pythonver_cmp(&ctx.db, "1.2.3-rc0", "1.2.3-rc0").await?
    );
    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_version_matches(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;

    assert!(version_matches(db, "1.0.2", VersionRange::Exact("1.0.2"), "python").await?);
    assert!(!version_matches(db, "1.0.2", VersionRange::Exact("1.0.0"), "python").await?);

    assert!(
        version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Unbounded, Version::Inclusive("1.0.2")),
            "python"
        )
        .await?
    );

    assert!(
        !version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Unbounded, Version::Exclusive("1.0.2")),
            "python"
        )
        .await?
    );

    assert!(
        version_matches(
            db,
            "1.0.2b2",
            VersionRange::Range(Version::Unbounded, Version::Exclusive("1.0.2")),
            "python"
        )
        .await?
    );

    assert!(
        version_matches(
            db,
            "1.0.2",
            VersionRange::Range(Version::Inclusive("1.0.2"), Version::Exclusive("1.0.5")),
            "python"
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
            "python"
        )
        .await?
    );

    Ok(())
}
