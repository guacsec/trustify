use rstest::rstest;
use sea_orm::{ConnectionTrait, Statement};
use test_context::AsyncTestContext;
use trustify_common::db::Database;
use trustify_test_context::TrustifyContext;

#[path = "common.rs"]
mod common;

async fn rpmver_cmp(db: &Database, left: &str, right: &str) -> Result<Option<i32>, anyhow::Error> {
    let result = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM rpmver_cmp( '{left}', '{right}' )
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

// Upstream RPM rpmvercmp test vectors from tests/rpmvercmp.at
#[rstest]
// basic numeric
#[case("1.0", "1.0", 0)]
#[case("1.0", "2.0", -1)]
#[case("2.0", "1.0", 1)]
#[case("2.0.1", "2.0.1", 0)]
#[case("2.0", "2.0.1", -1)]
#[case("2.0.1", "2.0", 1)]
// alpha suffixes
#[case("2.0.1a", "2.0.1a", 0)]
#[case("2.0.1a", "2.0.1", 1)]
#[case("2.0.1", "2.0.1a", -1)]
// mixed alpha-numeric
#[case("5.5p1", "5.5p1", 0)]
#[case("5.5p1", "5.5p2", -1)]
#[case("5.5p10", "5.5p1", 1)]
#[case("10xyz", "10.1xyz", -1)]
#[case("xyz.4", "8", -1)]
// leading zeros
#[case("10.0001", "10.0001", 0)]
#[case("10.0001", "10.1", 0)]
#[case("10.1", "10.0001", 0)]
#[case("10.0001", "10.0039", -1)]
// separator equivalence
#[case("2_0", "2_0", 0)]
#[case("2.0", "2_0", 0)]
#[case("a+", "a_", 0)]
#[case("+a", "_a", 0)]
#[case("+", "_", 0)]
// tilde
#[case("1.0~rc1", "1.0~rc1", 0)]
#[case("1.0~rc1", "1.0", -1)]
#[case("1.0", "1.0~rc1", 1)]
#[case("1.0~rc1", "1.0~rc2", -1)]
#[case("1.0~rc1~git123", "1.0~rc1", -1)]
// caret
#[case("1.0^", "1.0^", 0)]
#[case("1.0^", "1.0", 1)]
#[case("1.0", "1.0^", -1)]
#[case("1.0^git1", "1.0", 1)]
#[case("1.0^git1", "1.0^git2", -1)]
#[case("1.0^git1", "1.01", -1)]
#[case("1.0^20160101", "1.0.1", -1)]
// mixed tilde + caret
#[case("1.0~rc1^git1", "1.0~rc1", 1)]
#[case("1.0^git1", "1.0^git1~pre", 1)]
#[case("1.0^git1~pre", "1.0^git1", -1)]
// epoch
#[case("1:1.0", "1:1.0", 0)]
#[case("1:1.0", "2.0", 1)]
#[case("2.0", "1:1.0", -1)]
#[case("0:1.0", "1.0", 0)]
#[case("1.0", "0:1.0", 0)]
#[case("2:1.0", "1:2.0", 1)]
#[case("1:2.0", "2:1.0", -1)]
#[case("1:1.0", "1:1.1", -1)]
#[case("1:1.1", "1:1.0", 1)]
#[test_log::test(tokio::test)]
async fn test_rpmver_cmp(
    #[case] a: &str,
    #[case] b: &str,
    #[case] expected: i32,
) -> Result<(), anyhow::Error> {
    let ctx = TrustifyContext::setup().await;
    let result = rpmver_cmp(&ctx.db, a, b).await?;
    assert_eq!(
        result,
        Some(expected),
        "rpmver_cmp('{a}', '{b}') = {result:?}, expected {expected}"
    );
    Ok(())
}
