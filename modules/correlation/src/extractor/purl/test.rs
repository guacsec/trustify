use super::*;
use crate::{
    extractor::Extractors,
    model::{CorrelationOptionKey, EnabledBy, RangeBound},
};
use sea_orm::TransactionTrait;
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_entity::{
    correlation_evidence, correlation_evidence_context,
    correlation_evidence_context::ContextSource,
    correlation_option::{self, CorrelationOptionKey as EntityOptionKey},
};
use trustify_test_context::TrustifyContext;

const S5_SBOM: &str =
    "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json";
const S5_VEX: &str = "scenarios/S5_positive_baseline_openssl_el8/vex/CVE-2023-0215.json.xz";

fn extractors() -> Extractors {
    Extractors::new(vec![Box::new(PurlExtractor)])
}

async fn extract_for_sbom(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<usize> {
    let tx = ctx.db.begin().await?;
    let count = extractors().extract_for_sbom(sbom_id, &tx).await?;
    tx.commit().await?;
    Ok(count)
}

async fn extract_for_advisory(ctx: &TrustifyContext, advisory_id: Uuid) -> anyhow::Result<usize> {
    let tx = ctx.db.begin().await?;
    let count = extractors().extract_for_advisory(advisory_id, &tx).await?;
    tx.commit().await?;
    Ok(count)
}

/// (node, vulnerability, type, status, confidence, matched value)
type Evidence = (
    String,
    String,
    String,
    AssertionStatus,
    f64,
    Option<MatchedValue>,
);

/// All PURL evidence of an SBOM (stated and derived by rules), sorted.
async fn load_evidence(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<Vec<Evidence>> {
    let rules = rule::rules(&ctx.db).await?;
    let mut evidence = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .filter(
            correlation_evidence::Column::Extractor.is_in(
                [PLAIN, STREAM]
                    .into_iter()
                    .chain(rules.iter().map(|r| r.id())),
            ),
        )
        .all(&ctx.db)
        .await?
        .into_iter()
        .map(|e| {
            Ok((
                e.node_id,
                e.vulnerability_id,
                e.extractor,
                e.status,
                e.confidence,
                e.matched_value
                    .map(serde_json::from_value::<MatchedValue>)
                    .transpose()?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    evidence.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));
    Ok(evidence)
}

/// Ranges of the given scheme, fixed in the given versions (exclusive upper bounds).
fn fixed_in(scheme: &str, versions: &[&str]) -> Vec<MatchedRange> {
    versions
        .iter()
        .map(|fixed| MatchedRange {
            scheme: scheme.into(),
            low: None,
            high: Some(RangeBound {
                version: (*fixed).into(),
                inclusive: false,
            }),
        })
        .collect()
}

/// Both directions must find matches and produce the same evidence rows.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn extract_both_directions(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document(S5_SBOM).await?;
    let advisory = ctx.ingest_document(S5_VEX).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;

    assert!(extract_for_sbom(ctx, sbom_id).await? > 0);
    let from_sbom = load_evidence(ctx, sbom_id).await?;
    assert!(!from_sbom.is_empty());

    correlation_evidence::Entity::delete_many()
        .exec(&ctx.db)
        .await?;

    assert!(extract_for_advisory(ctx, advisory_id).await? > 0);
    assert_eq!(load_evidence(ctx, sbom_id).await?, from_sbom);

    Ok(())
}

/// Red Hat's `fixed`, read as `first_fixed`: affected before.
const FIXED_AS_FIRST_FIXED_BEFORE: &str = "purl_fixed_as_first_fixed_before";

/// The default option reading Red Hat's `fixed` as `first_fixed` (see `m0002550`).
fn redhat_first_fixed() -> EnabledBy {
    EnabledBy {
        option_id: Uuid::parse_str("019dc7a4-6a00-7000-8000-000000000003").expect("valid UUID"),
        key: CorrelationOptionKey::FixedIsFirstFixed,
        publisher_namespace: "https://www.redhat.com".into(),
        reason: Some(
            "Red Hat states `fixed` only for the build fixing a vulnerability in a product \
             stream: earlier builds of the stream are affected, later ones are fixed."
                .into(),
        ),
    }
}

const S9_VEX: &str = "scenarios/S9_substream_openssl_el8/vex/CVE-2023-0286.json.xz";

/// Ingest the documents, extract from the SBOM, and return its PURL evidence.
async fn evidence_of(
    ctx: &TrustifyContext,
    sbom: &str,
    vex: &str,
) -> anyhow::Result<Vec<Evidence>> {
    let sbom = ctx.ingest_document(sbom).await?;
    ctx.ingest_document(vex).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    extract_for_sbom(ctx, sbom_id).await?;
    load_evidence(ctx, sbom_id).await
}

/// Red Hat only states fixed versions. An `el8` package is affected by the `el8_*` fixes it is
/// below (sharing the major only), not by the `el9_*` ones.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_major(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(ctx, S5_SBOM, S5_VEX).await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0215".to_string(),
            FIXED_AS_FIRST_FIXED_BEFORE.to_string(),
            AssertionStatus::Affected,
            // 0.72, in RHEL 8 by the PURL's `distro=rhel-8.10` (0.85 × 0.9)
            0.55,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: fixed_in("rpm", &["1:1.1.1k-9.el8_6", "1:1.1.1k-9.el8_7"]),
                enabled_by: Some(redhat_first_fixed()),
            }),
        ),]
    );

    Ok(())
}

/// A later build of the stream is fixed from Red Hat's fix on, as the option reads it as
/// `first_fixed`.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_later_build(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(ctx, "correlation/openssl_el8_newer.cdx.json", S5_VEX).await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0215".to_string(),
            "purl_fixed_as_first_fixed".to_string(),
            AssertionStatus::Fixed,
            // 0.8 (`el8` and `el8_7` share the major only) × 0.9, in RHEL 8 by the PURL's
            // `distro=rhel-8.10` (0.85 × 0.9). The `el8_6` fix is stated for RHEL 8.6 EUS, a product
            // the package isn't in.
            0.55,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: vec![MatchedRange {
                    scheme: "rpm".into(),
                    low: Some(RangeBound {
                        version: "1:1.1.1k-9.el8_7".into(),
                        inclusive: true,
                    }),
                    high: None,
                }],
                enabled_by: Some(redhat_first_fixed()),
            }),
        )]
    );

    Ok(())
}

/// A build of a later minor is fixed from Red Hat's mainline fix of an earlier minor on, as the
/// mainline's minors are one line, and nothing is stated for its own stream (`el8_8`). The `el8_6`
/// fix is stated for RHEL 8.6 EUS, a product the package isn't in.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_later_minor(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(ctx, "correlation/openssl_el8_minor.cdx.json", S5_VEX).await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0215".to_string(),
            "purl_fixed_as_first_fixed".to_string(),
            AssertionStatus::Fixed,
            // 0.8 (another minor) × 0.9, in RHEL 8 by the PURL's `distro=rhel-8.8` (0.85 × 0.9)
            0.55,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: vec![MatchedRange {
                    scheme: "rpm".into(),
                    low: Some(RangeBound {
                        version: "1:1.1.1k-9.el8_7".into(),
                        inclusive: true,
                    }),
                    high: None,
                }],
                enabled_by: Some(redhat_first_fixed()),
            }),
        )]
    );

    Ok(())
}

/// Without the option, Red Hat's `fixed` is only the fixed version.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_option_disabled(ctx: &TrustifyContext) -> anyhow::Result<()> {
    correlation_option::Entity::update_many()
        .col_expr(correlation_option::Column::Value, Expr::value(json!(false)))
        .filter(correlation_option::Column::Key.eq(EntityOptionKey::FixedIsFirstFixed))
        .exec(&ctx.db)
        .await?;

    assert_eq!(evidence_of(ctx, S5_SBOM, S5_VEX).await?, vec![]);
    assert_eq!(
        evidence_of(ctx, "correlation/openssl_el8_newer.cdx.json", S5_VEX).await?,
        vec![]
    );

    Ok(())
}

/// An `el8_2` package below the fix is affected by the `el8_2` fix only, not the GA (`el8_7`) one.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_exact(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(
            ctx,
            "scenarios/S9_substream_openssl_el8/sbom_openssl_el8.2_below-fix.cdx.json",
            S9_VEX
        )
        .await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0286".to_string(),
            FIXED_AS_FIRST_FIXED_BEFORE.to_string(),
            AssertionStatus::Affected,
            // 0.9, stated for RHEL 8.2 EUS, which isn't compared with `enterprise_linux` (×0.7)
            0.63,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: fixed_in("rpm", &["1:1.1.1c-21.el8_2"]),
                enabled_by: Some(redhat_first_fixed()),
            }),
        ),]
    );

    Ok(())
}

/// A package at the fixed version matches the stated fixed version, and Red Hat's fix read as
/// `first_fixed`, as it is in the fix's own stream (`el8_2`).
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_at_fix(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let fix = "1:1.1.1c-21.el8_2";
    assert_eq!(
        evidence_of(
            ctx,
            "scenarios/S9_substream_openssl_el8/sbom_openssl_el8.2_patched.cdx.json",
            S9_VEX
        )
        .await?,
        vec![
            (
                "pkg-openssl".to_string(),
                "CVE-2023-0286".to_string(),
                "purl_fixed_as_first_fixed".to_string(),
                AssertionStatus::Fixed,
                // 0.9, stated for RHEL 8.2 EUS, which isn't compared with `enterprise_linux` (×0.7)
                0.63,
                Some(MatchedValue {
                    identifier: "pkg:rpm/redhat/openssl".into(),
                    ranges: vec![MatchedRange {
                        scheme: "rpm".into(),
                        low: Some(RangeBound {
                            version: fix.into(),
                            inclusive: true,
                        }),
                        high: None,
                    }],
                    enabled_by: Some(redhat_first_fixed()),
                }),
            ),
            (
                "pkg-openssl".to_string(),
                "CVE-2023-0286".to_string(),
                STREAM.to_string(),
                AssertionStatus::Fixed,
                // stated for RHEL 8.2 EUS, which isn't compared with `enterprise_linux` (×0.7)
                0.7,
                Some(MatchedValue {
                    identifier: "pkg:rpm/redhat/openssl".into(),
                    ranges: vec![MatchedRange {
                        scheme: "rpm".into(),
                        low: Some(RangeBound {
                            version: fix.into(),
                            inclusive: true,
                        }),
                        high: Some(RangeBound {
                            version: fix.into(),
                            inclusive: true,
                        }),
                    }],
                    enabled_by: None,
                }),
            ),
        ]
    );

    Ok(())
}

/// Stated ranges are scoped by stream too: an `el8` package matches the `el8_6` range (sharing the
/// major only), not the `el9_0` one. The publisher isn't Red Hat, so no rule applies.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn stated_stream_range(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(ctx, S5_SBOM, "correlation/stream-ranges.json").await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0215".to_string(),
            STREAM.to_string(),
            AssertionStatus::Affected,
            0.8,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: fixed_in("rpm", &["1:1.1.1k-9.el8_6"]),
                enabled_by: None,
            }),
        )]
    );

    Ok(())
}

/// A non-RPM package is matched by version range only, and reported as plain evidence.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn plain_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx
        .ingest_document(
            "scenarios/S6_positive_baseline_osv_urllib3/sbom_urllib3_affected.cdx.json",
        )
        .await?;
    ctx.ingest_document("scenarios/S6_positive_baseline_osv_urllib3/osv/GHSA-g4mx-q9vg-27p4.json")
        .await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    assert!(extract_for_sbom(ctx, sbom_id).await? > 0);

    assert_eq!(
        load_evidence(ctx, sbom_id).await?,
        vec![(
            "pkg-urllib3".to_string(),
            "CVE-2023-45803".to_string(),
            PLAIN.to_string(),
            AssertionStatus::Affected,
            1.0,
            Some(MatchedValue {
                identifier: "pkg:pypi/urllib3".into(),
                ranges: vec![
                    MatchedRange {
                        scheme: "generic".into(),
                        low: Some(RangeBound {
                            version: "1.26.17".into(),
                            inclusive: true,
                        }),
                        high: Some(RangeBound {
                            version: "1.26.17".into(),
                            inclusive: true,
                        }),
                    },
                    MatchedRange {
                        scheme: "python".into(),
                        low: None,
                        high: Some(RangeBound {
                            version: "1.26.18".into(),
                            inclusive: false,
                        }),
                    },
                ],
                enabled_by: None,
            }),
        )]
    );

    Ok(())
}

/// OSV only states the affected versions, with a versionless PURL identifying the package, not
/// meaning all versions. A version outside of the affected set (here above the fix) gets no
/// evidence: not from the fix, and not as any version.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn osv_outside_affected_set(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx
        .ingest_document(
            "scenarios/S6_positive_baseline_osv_urllib3/sbom_urllib3_abovefix.cdx.json",
        )
        .await?;
    ctx.ingest_document("scenarios/S6_positive_baseline_osv_urllib3/osv/GHSA-g4mx-q9vg-27p4.json")
        .await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    extract_for_sbom(ctx, sbom_id).await?;

    assert_eq!(load_evidence(ctx, sbom_id).await?, vec![]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn no_match_without_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document(S5_SBOM).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    let count = extract_for_sbom(ctx, sbom_id).await?;
    assert_eq!(count, 0, "no advisory means no matches");

    Ok(())
}

const SUSE_OLD_SBOM: &str =
    "scenarios/S23_suse_codestream_openssl/sbom/bci-base_15.6.47.11.1.cdx.json";
const SUSE_NEW_SBOM: &str =
    "scenarios/S23_suse_codestream_openssl/sbom/bci-base_15.6.47.26.19.cdx.json";
const SUSE_VEX: &str = "scenarios/S23_suse_codestream_openssl/vex/cve-2024-6119.json.xz";

/// The SLE 15 SP6 `openssl-3` packages of the official SBOMs: (node, name).
const SUSE_OLD_PACKAGES: [(&str, &str); 3] = [
    (
        "pkg:libopenssl-3-fips-provider-cfaacc362f4a214cbf95e206d26685d9",
        "libopenssl-3-fips-provider",
    ),
    (
        "pkg:libopenssl3-426db71183a22234f82854c990f2eacf",
        "libopenssl3",
    ),
    (
        "pkg:openssl-3-74fdf8be9af579e40f0343324a1a4d33",
        "openssl-3",
    ),
];
const SUSE_NEW_PACKAGES: [(&str, &str); 3] = [
    (
        "pkg:rpm/libopenssl-3-fips-provider-6968892f34af1cade0d1e3335998bacb",
        "libopenssl-3-fips-provider",
    ),
    (
        "pkg:rpm/libopenssl3-9e046a27101d2904cfe553dc6054e2dc",
        "libopenssl3",
    ),
    (
        "pkg:rpm/openssl-3-d4d5f859ac5fb640bc297892e9d9120a",
        "openssl-3",
    ),
];

/// SUSE's fix of the SLE 15 SP6 codestream for CVE-2024-6119.
const SUSE_SP6_FIX: &str = "3.1.4-150600.5.15.1";

/// The `openssl` package of the SBOM, which SUSE states as not affected, for all versions.
/// The evidence type of versionless PURLs, read as all versions.
const ANY_VERSION: &str = "purl_any_version";

/// The default option enabling versionless PURLs of a publisher (see the migration creating
/// `correlation_option`).
fn versionless(id: &str, publisher_namespace: &str, reason: &str) -> EnabledBy {
    EnabledBy {
        option_id: Uuid::parse_str(id).expect("valid UUID"),
        key: CorrelationOptionKey::VersionlessPurl,
        publisher_namespace: publisher_namespace.into(),
        reason: Some(reason.into()),
    }
}

fn redhat_versionless() -> EnabledBy {
    versionless(
        "019dc7a4-6a00-7000-8000-000000000001",
        "https://www.redhat.com",
        "Red Hat states the status of a component in a product with a versionless PURL, meaning all versions.",
    )
}

fn suse_versionless() -> EnabledBy {
    versionless(
        "019dc7a4-6a00-7000-8000-000000000002",
        "https://www.suse.com",
        "SUSE states the status of a package in a product with a versionless PURL, meaning all versions.",
    )
}

/// SUSE states the meta package `openssl` as not affected in SLE 15 SP6, with a versionless PURL.
/// The SBOM's packages are in SP6 by their `distro=sles-15.6` qualifier: 0.7 × 0.85 × 0.9.
fn suse_openssl_not_affected(node: &str) -> Evidence {
    (
        node.to_string(),
        "CVE-2024-6119".to_string(),
        ANY_VERSION.to_string(),
        AssertionStatus::NotAffected,
        0.54,
        Some(MatchedValue {
            identifier: "pkg:rpm/suse/openssl".into(),
            ranges: vec![MatchedRange {
                scheme: "rpm".into(),
                low: None,
                high: None,
            }],
            enabled_by: Some(suse_versionless()),
        }),
    )
}

/// An SP6 package before the SP6 fix is affected by that fix only. The fixes of the other
/// codestreams in the same document (SP4, SP5, SP7, 16.0, Micro, Tumbleweed) don't apply,
/// although e.g. `3.1.4-150600.5.7.1` is "newer" than Tumbleweed's `3.1.4-13.1`.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn suse_recommended_codestream(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let mut expected = SUSE_OLD_PACKAGES
        .iter()
        .map(|(node, name)| {
            (
                node.to_string(),
                "CVE-2024-6119".to_string(),
                "purl_suse_recommended_before".to_string(),
                AssertionStatus::Affected,
                // 0.9, in SLE 15 SP6 by the PURL's `distro=sles-15.6` (0.85 × 0.9)
                0.69,
                Some(MatchedValue {
                    identifier: format!("pkg:rpm/suse/{name}"),
                    ranges: fixed_in("rpm", &[SUSE_SP6_FIX]),
                    enabled_by: None,
                }),
            )
        })
        .collect::<Vec<_>>();
    expected.push(suse_openssl_not_affected(
        "pkg:openssl-0907d1fb499114c5df61bf90f42de3cc",
    ));
    expected.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));

    assert_eq!(evidence_of(ctx, SUSE_OLD_SBOM, SUSE_VEX).await?, expected);

    Ok(())
}

/// A later build of the same codestream is fixed from the recommended version on.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn suse_recommended_later_build(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let mut expected = SUSE_NEW_PACKAGES
        .iter()
        .map(|(node, name)| {
            (
                node.to_string(),
                "CVE-2024-6119".to_string(),
                "purl_suse_recommended".to_string(),
                AssertionStatus::Fixed,
                // 0.9, in SLE 15 SP6 by the PURL's `distro=sles-15.6` (0.85 × 0.9)
                0.69,
                Some(MatchedValue {
                    identifier: format!("pkg:rpm/suse/{name}"),
                    ranges: vec![MatchedRange {
                        scheme: "rpm".into(),
                        low: Some(RangeBound {
                            version: SUSE_SP6_FIX.into(),
                            inclusive: true,
                        }),
                        high: None,
                    }],
                    enabled_by: None,
                }),
            )
        })
        .collect::<Vec<_>>();
    expected.push(suse_openssl_not_affected(
        "pkg:rpm/openssl-0907d1fb499114c5df61bf90f42de3cc",
    ));
    expected.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));

    assert_eq!(evidence_of(ctx, SUSE_NEW_SBOM, SUSE_VEX).await?, expected);

    Ok(())
}

const RANGES_SBOM: &str = "csaf/ranges/vers-and-vls.cdx.json";
const RANGES_VEX: &str = "csaf/ranges/vers-and-vls.json";

/// A vls range (`<4.2`) states no versioning scheme, so it only matches through `purl_vls_range`,
/// with the scheme of the PURL type (`npm`) and a lower confidence. A vers range (`vers:npm/<2.0.0`)
/// matches as stated. The platform of a relationship is no subject of the status.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn vls_range(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let below = |scheme: &str, version: &str| {
        vec![MatchedRange {
            scheme: scheme.into(),
            low: None,
            high: Some(RangeBound {
                version: version.into(),
                inclusive: false,
            }),
        }]
    };

    assert_eq!(
        evidence_of(ctx, RANGES_SBOM, RANGES_VEX).await?,
        vec![
            (
                "example-app-1.0.0".to_string(),
                "CVE-2099-20001".to_string(),
                PLAIN.to_string(),
                AssertionStatus::Affected,
                // stated as installed on a platform, which the SBOM doesn't name (×0.7)
                0.7,
                Some(MatchedValue {
                    identifier: "pkg:npm/example-app".into(),
                    ranges: below("semver", "2.0.0"),
                    enabled_by: None,
                }),
            ),
            (
                "example-lib-4.1".to_string(),
                "CVE-2099-20001".to_string(),
                "purl_vls_range".to_string(),
                AssertionStatus::Affected,
                0.6,
                Some(MatchedValue {
                    identifier: "pkg:npm/example-lib".into(),
                    ranges: below("npm", "4.2"),
                    enabled_by: None,
                }),
            ),
        ]
    );

    Ok(())
}

/// CSAF statuses stating a single version (`first_fixed`, `first_affected`, `last_affected`) mean
/// a range from or up to that version, of the same stream: the `el9_0` package matches none of
/// them. `under_investigation` is stated for that exact version.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn csaf_single_version_statuses(ctx: &TrustifyContext) -> anyhow::Result<()> {
    const VERSION: &str = "1:1.1.1k-9.el8_6";
    let bound = |inclusive| {
        Some(RangeBound {
            version: VERSION.into(),
            inclusive,
        })
    };
    let from = MatchedRange {
        scheme: "rpm".into(),
        low: bound(true),
        high: None,
    };
    let before = MatchedRange {
        scheme: "rpm".into(),
        low: None,
        high: bound(false),
    };
    let up_to = MatchedRange {
        scheme: "rpm".into(),
        low: None,
        high: bound(true),
    };
    let exact = MatchedRange {
        scheme: "rpm".into(),
        low: bound(true),
        high: bound(true),
    };
    let evidence = |node: &str,
                    vulnerability: &str,
                    extractor: &str,
                    status,
                    confidence,
                    range: &MatchedRange| {
        (
            node.to_string(),
            vulnerability.to_string(),
            extractor.to_string(),
            status,
            confidence,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: vec![range.clone()],
                enabled_by: None,
            }),
        )
    };

    use AssertionStatus::{Affected, Fixed, UnderInvestigation};
    assert_eq!(
        evidence_of(
            ctx,
            "csaf/statuses/openssl.cdx.json",
            "csaf/statuses/first-last.json"
        )
        .await?,
        vec![
            evidence(
                "openssl-12",
                "CVE-2099-30001",
                "purl_first_fixed",
                Fixed,
                1.0,
                &from
            ),
            evidence(
                "openssl-12",
                "CVE-2099-30002",
                "purl_first_affected",
                Affected,
                0.9,
                &from
            ),
            evidence(
                "openssl-5",
                "CVE-2099-30001",
                "purl_first_fixed_before",
                Affected,
                0.9,
                &before
            ),
            evidence(
                "openssl-5",
                "CVE-2099-30003",
                "purl_last_affected",
                Affected,
                0.9,
                &up_to
            ),
            evidence(
                "openssl-9",
                "CVE-2099-30001",
                "purl_first_fixed",
                Fixed,
                1.0,
                &from
            ),
            evidence(
                "openssl-9",
                "CVE-2099-30002",
                "purl_first_affected",
                Affected,
                0.9,
                &from
            ),
            evidence(
                "openssl-9",
                "CVE-2099-30003",
                "purl_last_affected",
                Affected,
                0.9,
                &up_to
            ),
            evidence(
                "openssl-9",
                "CVE-2099-30004",
                STREAM,
                UnderInvestigation,
                1.0,
                &exact
            ),
        ]
    );

    Ok(())
}

const RH_VERSIONLESS_VEX: &str = "csaf/versionless/redhat.json";
const GOLANG_SBOM: &str =
    "scenarios/S16_crossscheme_purlquery_golang/sbom_golang_rpm_storage3.cdx.json";

/// Red Hat states the status of a component in a product with a versionless PURL. With the
/// default option, it applies to all versions, and the evidence names the option.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn versionless_redhat(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(ctx, GOLANG_SBOM, RH_VERSIONLESS_VEX).await?,
        vec![(
            "pkg-golang".to_string(),
            "CVE-2023-44487".to_string(),
            ANY_VERSION.to_string(),
            AssertionStatus::Affected,
            // 0.7 × 0.9: the context is the CPE of the root component, depending on the package
            0.63,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/golang".into(),
                ranges: vec![MatchedRange {
                    scheme: "generic".into(),
                    low: None,
                    high: None,
                }],
                enabled_by: Some(redhat_versionless()),
            }),
        )]
    );

    // the evidence is linked to the context, through the root component's CPE (which is also the
    // describing CPE, a less specific source of the same CPE)
    let links = correlation_evidence_context::Entity::find()
        .all(&ctx.db)
        .await?
        .into_iter()
        .map(|link| {
            (
                link.source,
                link.distance,
                link.node_identifier,
                link.context_identifier,
                link.confidence,
            )
        })
        .collect::<Vec<_>>();
    let storage = "cpe:2.3:a:redhat:storage:3:*:*:*:*:*:*:*".to_string();
    assert_eq!(
        links,
        vec![(
            ContextSource::AncestorNode,
            1,
            storage.clone(),
            storage,
            0.9
        )]
    );

    Ok(())
}

/// Without an enabled option for the publisher, a versionless PURL matches nothing.
#[test_context(TrustifyContext)]
#[rstest::rstest]
#[case::deleted(None)]
#[case::disabled(Some(serde_json::Value::Bool(false)))]
#[test_log::test(actix_web::test)]
async fn versionless_not_enabled(
    ctx: &TrustifyContext,
    #[case] value: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    use sea_orm::ActiveValue::Set;
    use trustify_entity::correlation_option;

    let publisher = correlation_option::Column::PublisherNamespace.eq("https://www.redhat.com");
    match value {
        None => {
            correlation_option::Entity::delete_many()
                .filter(publisher)
                .exec(&ctx.db)
                .await?;
        }
        Some(value) => {
            correlation_option::Entity::update_many()
                .set(correlation_option::ActiveModel {
                    value: Set(value),
                    ..Default::default()
                })
                .filter(publisher)
                .exec(&ctx.db)
                .await?;
        }
    }

    assert_eq!(
        evidence_of(ctx, GOLANG_SBOM, RH_VERSIONLESS_VEX).await?,
        vec![]
    );

    Ok(())
}

/// A publisher without an option: its versionless PURLs match nothing.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn versionless_other_publisher(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let mut vex: serde_json::Value =
        serde_json::from_slice(&trustify_test_context::document_bytes(RH_VERSIONLESS_VEX).await?)?;
    vex["document"]["publisher"]["namespace"] = "https://example.com".into();

    let sbom = ctx.ingest_document(GOLANG_SBOM).await?;
    ctx.ingest_json(vex).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    extract_for_sbom(ctx, sbom_id).await?;

    assert_eq!(load_evidence(ctx, sbom_id).await?, vec![]);

    Ok(())
}
