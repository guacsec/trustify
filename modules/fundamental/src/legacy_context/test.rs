use super::filter;
use sea_orm::ConnectionTrait;
use serde_json::{Value, json};
use test_context::test_context;
use trustify_common::{db::sql, purl::Purl};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

mod regression;

fn rhel() -> Value {
    json!({
        "id": Uuid::nil(), "part": "o", "vendor": "redhat",
        "product": "enterprise_linux", "version": "10", "update": "*",
        "edition": "*", "language": "*", "sw_edition": "*", "target_sw": "*",
        "target_hw": "*", "other": "*"
    })
}

async fn matches(
    ctx: &TrustifyContext,
    purl: &str,
    context: Value,
    bound: Option<&str>,
    explicit: bool,
    missing: bool,
) -> anyhow::Result<bool> {
    let purl: Purl = purl.parse()?;
    let predicate = filter(
        "$2::uuid",
        "$3::jsonb",
        "$4::text",
        "$5::boolean",
        "$6::boolean",
        "$5::boolean",
    );
    // Shadow the CPE relation with one synthetic row. This exercises the exact
    // production predicate without depending on ingestion or live assertions.
    let query = format!(
        "WITH cpe AS (SELECT * FROM jsonb_populate_record(NULL::public.cpe, $1::jsonb)) \
         SELECT {predicate} AS matches"
    );
    let result = ctx
        .db
        .query_one_raw(sql(
            &query,
            vec![
                context.into(),
                Uuid::nil().into(),
                Value::from(&purl).into(),
                bound.map(str::to_owned).into(),
                explicit.into(),
                missing.into(),
            ],
        ))
        .await?
        .unwrap();
    Ok(result.try_get("", "matches")?)
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn rhel_context_is_package_local(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let purl = "pkg:rpm/redhat/libbrotli@1.1.0-8.el10_2?arch=x86_64&distro=rhel-10.2";
    for missing in [false, true] {
        // A private image CPE (explicit=false) and an absent root are equivalent
        // for a package whose own qualifiers identify RHEL.
        assert!(matches(ctx, purl, rhel(), None, false, missing).await?);
        for (attribute, value) in [
            ("vendor", "other"),
            ("product", "hummingbird"),
            ("version", "9"),
            ("version", "11"),
            ("edition", "fastdatapath"),
            ("update", "eus"),
            ("sw_edition", "server"),
            ("language", "en-us"),
            ("target_hw", "aarch64"),
            ("target_sw", "other"),
            ("other", "restricted"),
            ("part", "h"),
        ] {
            let mut context = rhel();
            context[attribute] = value.into();
            assert!(
                !matches(ctx, purl, context, None, false, missing).await?,
                "{attribute}={value}"
            );
        }
        for (attribute, value) in [
            ("version", "10.2"),
            ("version", "*"),
            ("part", "a"),
            ("target_hw", "x86_64"),
        ] {
            let mut context = rhel();
            context[attribute] = value.into();
            assert!(matches(ctx, purl, context, None, false, missing).await?);
        }
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn rpm_hints_and_streams_are_conservative(ctx: &TrustifyContext) -> anyhow::Result<()> {
    for purl in [
        "pkg:rpm/redhat/libbrotli@1.1.0-8.el10_2?distro=rhel-10.2",
        "pkg:rpm/redhat/libbrotli@1.1.0-8.el10_2",
        "pkg:rpm/redhat/libbrotli@1:1.1.0-8.el10_2?distro=rhel-10",
        "pkg:rpm/redhat/libbrotli@1.1.0-8?distro=rhel-10.2",
    ] {
        assert!(
            matches(ctx, purl, rhel(), None, false, false).await?,
            "{purl}"
        );
    }
    for distro in [
        "rhel-9",
        "rhel-11",
        "rhel-invalid",
        "rhel-10.2.3",
        "sles-15",
    ] {
        let purl = format!("pkg:rpm/redhat/libbrotli@1.1.0-8.el10_2?distro={distro}");
        assert!(
            !matches(ctx, &purl, rhel(), None, false, true).await?,
            "{purl}"
        );
    }
    let purl = "pkg:rpm/redhat/libbrotli@1.1.0-8.el10_2?distro=rhel-10.2";
    for bound in [
        "1.1.0-8.el10_2.1",
        "1.1.0-8.el10_1",
        "1.1.0-8.el10",
        "1.1.0",
    ] {
        assert!(
            matches(ctx, purl, rhel(), Some(bound), false, false).await?,
            "{bound}"
        );
    }
    for bound in [
        "1.2.0-1.el9",
        "1.2.0-1.el11",
        "1.2.0-1.hum1",
        "1.2.0-1.fc40",
    ] {
        assert!(
            !matches(ctx, purl, rhel(), Some(bound), false, true).await?,
            "{bound}"
        );
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn unrelated_packages_keep_legacy_context_rules(ctx: &TrustifyContext) -> anyhow::Result<()> {
    for purl in [
        "pkg:pypi/example@1.0",
        "pkg:rpm/other/example@1.0-1",
        "pkg:rpm/redhat/example@1.0-1",
    ] {
        for (explicit, missing, expected) in [
            (false, false, false),
            (true, false, true),
            (false, true, true),
        ] {
            assert_eq!(
                matches(ctx, purl, rhel(), None, explicit, missing).await?,
                expected,
                "{purl}"
            );
        }
    }
    // Invalid RPM hints can still use independently proven explicit context,
    // but must never reopen the unrestricted no-describing-CPE fallback.
    let invalid = "pkg:rpm/redhat/example@1.0-1.el10?distro=invalid";
    assert!(!matches(ctx, invalid, rhel(), None, false, true).await?);
    assert!(matches(ctx, invalid, rhel(), None, true, false).await?);
    Ok(())
}
