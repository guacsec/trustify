use super::*;
use crate::{
    extractor::{Extractors, SourceAssertionRef},
    model::{
        ContextSource as ApiContextSource, CorrelationOptionKey, EnabledBy, RangeBound,
        StreamRelation,
    },
};
use sea_orm::{
    LoaderTrait, QueryOrder, TransactionTrait,
    sea_query::{PostgresQueryBuilder, Query},
};
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_common::{
    db::sql,
    rpm::{Evr, stream_major},
};
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
    let rules = rules(&ctx.db).await?;
    let mut evidence = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .filter(
            correlation_evidence::Column::Extractor.is_in(
                [PLAIN, STREAM, DEFAULT]
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
    evidence.sort_by(|a, b| {
        (&a.0, &a.1, &a.2, a.5.as_ref().map(|v| &v.identifier)).cmp(&(
            &b.0,
            &b.1,
            &b.2,
            b.5.as_ref().map(|v| &v.identifier),
        ))
    });
    Ok(evidence)
}

/// Compare the range-rule behavior independently of source PURL presentation. The module and
/// provenance tests below use raw evidence; these existing policy tests aggregate its ranges by
/// base identity, as they did before assertions retained their original qualified PURLs.
async fn range_evidence(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<Vec<Evidence>> {
    let mut result: Vec<Evidence> = Vec::new();
    for mut evidence in load_evidence(ctx, sbom_id).await? {
        if let Some(value) = &mut evidence.5 {
            let purl = value.identifier.parse::<Purl>()?;
            value.identifier = purl.to_base().to_string();
        }
        if let Some(existing) = result.iter_mut().find(|e| {
            e.0 == evidence.0
                && e.1 == evidence.1
                && e.2 == evidence.2
                && e.3 == evidence.3
                && e.5.as_ref().map(|v| (&v.identifier, &v.enabled_by))
                    == evidence.5.as_ref().map(|v| (&v.identifier, &v.enabled_by))
        }) {
            existing.4 = existing.4.max(evidence.4);
            if let (Some(value), Some(additional)) = (&mut existing.5, evidence.5) {
                value.ranges.extend(additional.ranges);
                value.ranges.sort();
                value.ranges.dedup();
            }
        } else {
            result.push(evidence);
        }
    }
    Ok(result)
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

/// Ad-hoc matching resolves an applicable range for a version absent from `versioned_purl`.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_identifier_matches_synthetic_purl_version(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let advisory = ctx.ingest_document(S5_VEX).await?;
    let identifier = IdentifierRef {
        kind: IdentifierKind::Purl,
        value: "pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=x86_64&distro=rhel-8.10&epoch=1".into(),
    };
    let purl = identifier.value.parse::<Purl>()?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;
    let tx = ctx.db.begin().await?;

    assert!(
        versioned_purl::Entity::find_by_id(purl.version_uuid())
            .one(&tx)
            .await?
            .is_none(),
        "test input must not have a persisted versioned_purl row"
    );

    let matches = PurlExtractor
        .match_identifiers(std::slice::from_ref(&identifier), &tx)
        .await?;
    let matched = matches
        .iter()
        .find(|matched| {
            matched.index == 0
                && matched.assertion.advisory_id == advisory_id
                && matched.assertion.vulnerability_id == "CVE-2023-0215"
                && matched.assertion.status == AssertionStatus::Affected
                && matched.assertion.matched_value.origin == AssertionOrigin::PublisherPolicy
        })
        .expect("the synthetic PURL should match the advisory's affected range");

    assert!(matched.assertion.confidence > 0.0);
    assert!(
        matched
            .assertion
            .source_assertions
            .iter()
            .any(|source| { matches!(source, SourceAssertionRef::Purl(_)) })
    );
    assert_eq!(
        matched.assertion.matched_value.identifier,
        "pkg:rpm/redhat/openssl"
    );

    Ok(())
}

/// Deprecated evidence is excluded for persisted and synthetic query versions alike.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_identifier_excludes_deprecated_purl_evidence(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let advisory = ctx.ingest_document(S5_VEX).await?;
    ctx.ingest_document(S5_SBOM).await?;
    let tx = ctx.db.begin().await?;
    let identifiers = [
        // The fixture SBOM persists this version; the other version stays synthetic.
        IdentifierRef {
            kind: IdentifierKind::Purl,
            value: "pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=x86_64&epoch=1".into(),
        },
        IdentifierRef {
            kind: IdentifierKind::Purl,
            value: "pkg:rpm/redhat/openssl@1.1.1k-6.el8_5?arch=x86_64&distro=rhel-8.10&epoch=1"
                .into(),
        },
    ];
    for (index, identifier) in identifiers.iter().enumerate() {
        assert_eq!(
            versioned_purl::Entity::find_by_id(identifier.value.parse::<Purl>()?.version_uuid())
                .one(&tx)
                .await?
                .is_some(),
            index == 0
        );
        assert!(
            !PurlExtractor
                .match_identifiers(std::slice::from_ref(identifier), &tx)
                .await?
                .is_empty()
        );
    }
    advisory::Entity::update_many()
        .col_expr(advisory::Column::Deprecated, Expr::value(true))
        .filter(advisory::Column::Id.eq(Uuid::parse_str(&advisory.id)?))
        .exec(&tx)
        .await?;
    assert!(
        PurlExtractor
            .match_identifiers(&identifiers, &tx)
            .await?
            .is_empty()
    );
    Ok(())
}

/// Verifies whole-collection matching exceeds the bind limit without losing input associations.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn match_identifiers_beyond_bind_parameter_limit(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{ActiveValue::Set, sea_query::OnConflict};
    use trustify_common::db::chunk::EntityChunkedIter;

    // Given 70,000 distinct persisted versions, with known matches beyond index 65,535.
    let advisory = ctx.ingest_document("osv/RUSTSEC-2021-0079.json").await?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;
    let mut identifiers = (0..70_000)
        .map(|index| IdentifierRef {
            kind: IdentifierKind::Purl,
            value: format!("pkg:generic/bind-limit-filler@0.0.{index}"),
        })
        .collect::<Vec<_>>();
    for (index, value) in [
        (0, "pkg:cargo/hyper@0.14.1"),
        (65_536, "pkg:cargo/hyper@0.14.2"),
        (69_999, "pkg:cargo/hyper@0.14.3"),
    ] {
        identifiers[index].value = value.into();
    }
    identifiers.push(identifiers[0].clone());
    identifiers.push(IdentifierRef {
        kind: IdentifierKind::Purl,
        value: "pkg:cargo/hyper@0.14.2?repository_url=https://example.com".into(),
    });
    let tx = ctx.db.begin().await?;
    let mut bases = BTreeMap::new();
    let mut versions = BTreeMap::new();
    for identifier in &identifiers {
        let purl = identifier.value.parse::<Purl>()?;
        bases
            .entry(purl.package_uuid())
            .or_insert_with(|| base_purl::ActiveModel {
                id: Set(purl.package_uuid()),
                r#type: Set(purl.ty.clone()),
                namespace: Set(purl.namespace.clone()),
                name: Set(purl.name.clone()),
            });
        versions
            .entry(purl.version_uuid())
            .or_insert_with(|| versioned_purl::ActiveModel {
                id: Set(purl.version_uuid()),
                base_purl_id: Set(purl.package_uuid()),
                version: Set(purl.effective_version()),
            });
    }
    for batch in bases.into_values().chunked() {
        base_purl::Entity::insert_many(batch)
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .exec_without_returning(&tx)
            .await?;
    }
    for batch in versions.into_values().chunked() {
        versioned_purl::Entity::insert_many(batch)
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .exec_without_returning(&tx)
            .await?;
    }

    // When matching the entire collection, as the SBOM extractor does.
    let matches = PurlExtractor.match_identifiers(&identifiers, &tx).await?;

    // Then exact versions, duplicate indices, and qualified inputs keep their affected evidence.
    assert_eq!(
        matches
            .iter()
            .map(|matched| matched.index)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 65_536, 69_999, 70_000, 70_001])
    );
    for matched in &matches {
        assert_eq!(matched.assertion.advisory_id, advisory_id);
        assert_eq!(matched.assertion.vulnerability_id, "CVE-2021-32714");
        assert_eq!(matched.assertion.status, AssertionStatus::Affected);
    }
    Ok(())
}

/// A node's PURLs are judged together, in both directions: a statement in the node's own stream
/// (here the `el8` fixes, for the `el8` PURL) suppresses the fallback to another minor of the same
/// major (the `el8_7` fix, for the `el8_8` PURL).
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn node_purls_are_judged_together(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let purl = |version: &str| {
        json!({
            "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
            "referenceLocator": format!("pkg:rpm/redhat/openssl@{version}?arch=x86_64&epoch=1"),
        })
    };
    let document = json!({
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "openssl", "documentNamespace": "https://example.com/spdx/openssl-two-purls",
        "creationInfo": { "created": "2025-01-01T00:00:00Z", "creators": ["Tool: test"] },
        "packages": [{
            "SPDXID": "SPDXRef-openssl", "name": "openssl", "versionInfo": "1:1.1.1k-7.el8",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [purl("1.1.1k-7.el8"), purl("1.1.1k-10.el8_8")],
        }],
        "relationships": [{
            "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-openssl",
        }],
    });
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_read(serde_json::to_vec(&document)?.as_slice())
            .await?
            .id,
    )?;
    let advisory_id = Uuid::parse_str(&ctx.ingest_document(S5_VEX).await?.id)?;

    extract_for_sbom(ctx, sbom_id).await?;
    let from_sbom = load_evidence(ctx, sbom_id).await?;
    // only the `el8` fixes, as for the `el8` PURL alone, not the `el8_7` fix as `fixed` for the
    // `el8_8` PURL
    assert_eq!(
        range_evidence(ctx, sbom_id).await?,
        vec![(
            "SPDXRef-openssl".to_string(),
            "CVE-2023-0215".to_string(),
            FIXED_AS_FIRST_FIXED_BEFORE.to_string(),
            AssertionStatus::Affected,
            // 0.72 (see `rh_fixed_major`), in RHEL 8 by the PURLs' release, as there is no
            // `distro` qualifier
            0.49,
            Some(MatchedValue {
                source_provider: None,
                origin: AssertionOrigin::PublisherPolicy,
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: fixed_in("rpm", &["1:1.1.1k-9.el8_7"]),
                enabled_by: Some(redhat_first_fixed()),
            }),
        )]
    );

    correlation_evidence::Entity::delete_many()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .exec(&ctx.db)
        .await?;
    extract_for_advisory(ctx, advisory_id).await?;
    assert_eq!(load_evidence(ctx, sbom_id).await?, from_sbom);

    Ok(())
}

/// Extracting an SBOM node by node, or writing its evidence after each node, yields the same
/// evidence as all at once.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn chunks_extract_like_one_chunk(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document(S5_SBOM).await?;
    ctx.ingest_documents([S5_VEX, S9_VEX]).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    assert!(extract_for_sbom(ctx, sbom_id).await? > 0);
    let at_once = load_evidence(ctx, sbom_id).await?;
    let contexts = evidence_contexts(ctx).await?;
    assert!(!contexts.is_empty());

    for (name, extractors) in [
        ("one identifier per chunk", extractors().with_chunk(1)),
        ("one match per write", extractors().with_match_batch(1)),
    ] {
        correlation_evidence::Entity::delete_many()
            .exec(&ctx.db)
            .await?;
        let tx = ctx.db.begin().await?;
        extractors.extract_for_sbom(sbom_id, &tx).await?;
        tx.commit().await?;
        assert_eq!(load_evidence(ctx, sbom_id).await?, at_once, "{name}");
        assert_eq!(evidence_contexts(ctx).await?, contexts, "{name}");
    }

    Ok(())
}

/// An evidence context, as text.
#[derive(Debug, PartialEq, FromQueryResult)]
struct ContextRow {
    row: String,
}

/// All evidence contexts, sorted.
async fn evidence_contexts(ctx: &TrustifyContext) -> anyhow::Result<Vec<ContextRow>> {
    Ok(ContextRow::find_by_statement(sql(
        "SELECT c::text AS row FROM correlation_evidence_context c ORDER BY 1",
        vec![],
    ))
    .all(&ctx.db)
    .await?)
}

/// Red Hat's `fixed`, read as `first_fixed`: affected before.
const FIXED_AS_FIRST_FIXED_BEFORE: &str = "purl_fixed_as_first_fixed_before";

/// The default option reading Red Hat's `fixed` as `first_fixed` (see `m0002500`).
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
    range_evidence(ctx, sbom_id).await
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
                source_provider: None,
                origin: AssertionOrigin::PublisherPolicy,
                identifier: "pkg:rpm/redhat/openssl".into(),
                // The el8_6 fix belongs to EUS, not this mainline package.
                ranges: fixed_in("rpm", &["1:1.1.1k-9.el8_7"]),
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
                source_provider: None,
                origin: AssertionOrigin::PublisherPolicy,
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
                source_provider: None,
                origin: AssertionOrigin::PublisherPolicy,
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
                source_provider: None,
                origin: AssertionOrigin::PublisherPolicy,
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
                    source_provider: None,
                    origin: AssertionOrigin::PublisherPolicy,
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
                    source_provider: None,
                    origin: AssertionOrigin::Stated,
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
                source_provider: None,
                origin: AssertionOrigin::Stated,
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: fixed_in("rpm", &["1:1.1.1k-9.el8_6"]),
                enabled_by: None,
            }),
        )]
    );

    Ok(())
}

/// A CVE record's default status (lodash, CVE-2026-2950: `unaffected`) applies to a version no
/// listed statement matches, and is shadowed where one does.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn default_status(ctx: &TrustifyContext) -> anyhow::Result<()> {
    const BASE: &str = "scenarios/S25_cve_package_url";
    ctx.ingest_document(&format!("{BASE}/cve/CVE-2026-2950.json"))
        .await?;

    let evidence = async |sbom: &str| -> anyhow::Result<Vec<Evidence>> {
        let sbom = ctx.ingest_document(&format!("{BASE}/{sbom}")).await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;
        extract_for_sbom(ctx, sbom_id).await?;
        load_evidence(ctx, sbom_id).await
    };
    let unbounded = MatchedRange {
        scheme: "generic".into(),
        low: None,
        high: None,
    };
    let provider = crate::model::ProviderIdentity {
        identifiers: vec![
            "container:cna".into(),
            "cve-org:ce714d77-add3-4f53-aff5-83d477b104bb".into(),
            "name:openjs".into(),
        ],
        name: Some("openjs".into()),
        unavailable: false,
    };

    // not listed: the default
    assert_eq!(
        evidence("sbom_lodash_4.17.21.cdx.json").await?,
        vec![(
            "pkg-lodash".to_string(),
            "CVE-2026-2950".to_string(),
            DEFAULT.to_string(),
            AssertionStatus::NotAffected,
            0.9,
            Some(MatchedValue {
                source_provider: Some(provider.clone()),
                origin: AssertionOrigin::Default,
                identifier: "pkg:npm/lodash".into(),
                ranges: vec![unbounded],
                enabled_by: None,
            }),
        )]
    );

    // listed as affected: the default doesn't apply
    assert_eq!(
        evidence("sbom_lodash_4.17.23.cdx.json").await?,
        vec![(
            "pkg-lodash".to_string(),
            "CVE-2026-2950".to_string(),
            PLAIN.to_string(),
            AssertionStatus::Affected,
            1.0,
            Some(MatchedValue {
                source_provider: Some(provider),
                origin: AssertionOrigin::Stated,
                identifier: "pkg:npm/lodash".into(),
                ranges: vec![MatchedRange {
                    scheme: "semver".into(),
                    low: Some(RangeBound {
                        version: "4.17.23".into(),
                        inclusive: true,
                    }),
                    high: Some(RangeBound {
                        version: "4.18.0".into(),
                        inclusive: false,
                    }),
                }],
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
                source_provider: None,
                origin: AssertionOrigin::Stated,
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
            source_provider: None,
            origin: AssertionOrigin::PublisherPolicy,
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
                    source_provider: None,
                    origin: AssertionOrigin::Inferred,
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
                    source_provider: None,
                    origin: AssertionOrigin::Inferred,
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
                    source_provider: None,
                    origin: AssertionOrigin::Stated,
                    identifier: "pkg:npm/example-app".into(),
                    ranges: below("npm", "2.0.0"),
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
                    source_provider: None,
                    origin: AssertionOrigin::Stated,
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
                source_provider: None,
                origin: if extractor != "purl_first_fixed_before" {
                    AssertionOrigin::Stated
                } else {
                    AssertionOrigin::Inferred
                },
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
                source_provider: None,
                origin: AssertionOrigin::PublisherPolicy,
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

/// Preserve module-specific assertions and compare qualifiers before grouping in either direction.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rpm_module_identity(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use trustify_entity::purl_status;
    use trustify_test_context::document_bytes;
    const SCENARIO: &str = "scenarios/S11_bareaffected_substream_firefox";
    let advisory_path = format!("{SCENARIO}/vex/CVE-2023-6135.json.xz");
    let advisory = ctx.ingest_document(&advisory_path).await?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;
    let original_rows = purl_status::Entity::find()
        .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
        .all(&ctx.db)
        .await?;
    let purls = original_rows
        .load_one(qualified_purl::Entity, &ctx.db)
        .await?;
    assert!(purls.iter().all(Option::is_some));
    let source_identifiers = purls
        .iter()
        .flatten()
        .map(|p| Purl::from(p.purl.clone()).to_string())
        .collect::<BTreeSet<_>>();
    let firefox_modules = purls
        .iter()
        .flatten()
        .filter(|p| p.purl.name == "firefox")
        .map(|p| p.purl.qualifiers.get("rpmmod").cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        firefox_modules,
        BTreeSet::from([None, Some("firefox:flatpak".into())])
    );
    assert!(ctx.ingest_document(&advisory_path).await?.duplicate);
    let mut repeated = purl_status::Entity::find()
        .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
        .all(&ctx.db)
        .await?;
    let mut original_rows = original_rows;
    original_rows.sort_by_key(|r| r.id);
    repeated.sort_by_key(|r| r.id);
    assert_eq!(original_rows, repeated);

    let mut sbom: serde_json::Value = serde_json::from_slice(
        &document_bytes(format!("{SCENARIO}/sbom_firefox_main_el8.cdx.json")).await?,
    )?;
    let original = sbom["components"][0].clone();
    let inputs = [
        (
            "base",
            "pkg:rpm/redhat/firefox@115.15.0-1.el8?arch=x86_64&distro=rhel-8.10",
        ),
        (
            "flatpak",
            "pkg:rpm/redhat/firefox@115.15.0-1.el8?arch=x86_64&distro=rhel-8.10&rpmmod=firefox:flatpak",
        ),
        (
            "other",
            "pkg:rpm/redhat/firefox@115.15.0-1.el8?arch=x86_64&distro=rhel-8.10&rpmmod=firefox:other",
        ),
    ];
    sbom["components"] = inputs
        .iter()
        .map(|(node, purl)| {
            let mut component = original.clone();
            component["bom-ref"] = (*node).into();
            component["purl"] = (*purl).into();
            component
        })
        .collect::<Vec<_>>()
        .into();
    sbom["dependencies"][0]["dependsOn"] = json!(["base", "flatpak", "other"]);
    let sbom_id = Uuid::parse_str(&ctx.ingest_json(sbom).await?.id)?;

    extract_for_sbom(ctx, sbom_id).await?;
    let from_sbom = load_evidence(ctx, sbom_id).await?;
    assert!(from_sbom.iter().all(|e| {
        e.5.as_ref()
            .is_some_and(|value| source_identifiers.contains(&value.identifier))
    }));
    let negatives = from_sbom
        .iter()
        .filter(|e| e.3 == AssertionStatus::NotAffected)
        .collect::<Vec<_>>();
    assert!(!negatives.is_empty());
    assert!(negatives.iter().all(|e| e.0 == "flatpak"));
    assert!(negatives.iter().all(|e| e.5.as_ref().is_some_and(|v| {
        v.identifier.parse::<Purl>().is_ok_and(|p| {
            p.qualifiers.get("rpmmod").map(String::as_str) == Some("firefox:flatpak")
        })
    })));
    for node in ["base", "flatpak", "other"] {
        // The unqualified positive remains applicable to each module variant.
        assert!(
            from_sbom
                .iter()
                .any(|e| e.0 == node && e.3 == AssertionStatus::Affected)
        );
    }

    correlation_evidence::Entity::delete_many()
        .exec(&ctx.db)
        .await?;
    extract_for_advisory(ctx, advisory_id).await?;
    assert_eq!(load_evidence(ctx, sbom_id).await?, from_sbom);

    let identifiers = inputs
        .iter()
        .map(|(_, value)| {
            vec![IdentifierRef {
                kind: IdentifierKind::Purl,
                value: (*value).into(),
            }]
        })
        .collect::<Vec<_>>();
    let tx = ctx.db.begin().await?;
    let matches = PurlExtractor.match_identifiers(&identifiers, &tx).await?;
    let negatives = matches
        .iter()
        .filter(|m| m.assertion.status == AssertionStatus::NotAffected)
        .collect::<Vec<_>>();
    assert!(!negatives.is_empty());
    assert!(negatives.iter().all(|m| m.component == 1));
    Ok(())
}

/// A binary RPM only matches assertions of its own architecture or its source package, in either
/// direction. A source package, or one without an architecture, matches all of them.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rpm_architecture(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use trustify_test_context::document_bytes;
    let advisory = ctx.ingest_document(S5_VEX).await?;

    let mut sbom: serde_json::Value = serde_json::from_slice(&document_bytes(S5_SBOM).await?)?;
    let original = sbom["components"][0].clone();
    let inputs = [
        (
            "x86_64",
            "pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=x86_64&epoch=1",
        ),
        (
            "aarch64",
            "pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=aarch64&epoch=1",
        ),
        (
            "src",
            "pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=src&epoch=1",
        ),
        ("none", "pkg:rpm/redhat/openssl@1.1.1k-7.el8?epoch=1"),
    ];
    sbom["components"] = inputs
        .iter()
        .map(|(node, purl)| {
            let mut component = original.clone();
            component["bom-ref"] = (*node).into();
            component["purl"] = (*purl).into();
            component
        })
        .collect::<Vec<_>>()
        .into();
    sbom["dependencies"][0]["dependsOn"] = json!(["x86_64", "aarch64", "src", "none"]);
    let sbom_id = Uuid::parse_str(&ctx.ingest_json(sbom).await?.id)?;

    /// The architecture of a matched advisory PURL.
    fn arch(identifier: &str) -> anyhow::Result<Option<String>> {
        Ok(identifier.parse::<Purl>()?.qualifiers.get("arch").cloned())
    }

    extract_for_sbom(ctx, sbom_id).await?;
    let from_sbom = load_evidence(ctx, sbom_id).await?;
    let mut archs = BTreeMap::<&str, BTreeSet<Option<String>>>::new();
    for evidence in &from_sbom {
        if let Some(value) = &evidence.5 {
            archs
                .entry(evidence.0.as_str())
                .or_default()
                .insert(arch(&value.identifier)?);
        }
    }
    let all = BTreeSet::from([
        Some("aarch64".to_string()),
        Some("ppc64le".to_string()),
        Some("s390x".to_string()),
        Some("src".to_string()),
        Some("x86_64".to_string()),
    ]);
    assert_eq!(
        archs,
        BTreeMap::from([
            (
                "aarch64",
                BTreeSet::from([Some("aarch64".to_string()), Some("src".to_string())])
            ),
            ("none", all.clone()),
            ("src", all),
            (
                "x86_64",
                BTreeSet::from([Some("src".to_string()), Some("x86_64".to_string())])
            ),
        ])
    );

    correlation_evidence::Entity::delete_many()
        .exec(&ctx.db)
        .await?;
    extract_for_advisory(ctx, Uuid::parse_str(&advisory.id)?).await?;
    assert_eq!(load_evidence(ctx, sbom_id).await?, from_sbom);

    let identifiers = inputs
        .iter()
        .map(|(_, value)| {
            vec![IdentifierRef {
                kind: IdentifierKind::Purl,
                value: (*value).into(),
            }]
        })
        .collect::<Vec<_>>();
    let tx = ctx.db.begin().await?;
    let matches = PurlExtractor.match_identifiers(&identifiers, &tx).await?;
    let mut by_identifier = BTreeMap::<&str, BTreeSet<Option<String>>>::new();
    // without context, the advisory's versionless PURLs (without an architecture) match too
    for m in &matches {
        if let Some(arch) = arch(&m.assertion.matched_value.identifier)? {
            by_identifier
                .entry(inputs[m.component].0)
                .or_default()
                .insert(Some(arch));
        }
    }
    assert_eq!(by_identifier, archs);

    Ok(())
}

/// The explicit S12 negative must not hide any cross-product below-fix evidence.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn thunderbird_control_has_no_evidence(ctx: &TrustifyContext) -> anyhow::Result<()> {
    const BASE: &str = "scenarios/S12_notaffected_ignored_thunderbird";
    let sbom = ctx
        .ingest_document(&format!("{BASE}/sbom_thunderbird_el8.cdx.json"))
        .await?;
    let advisory = ctx
        .ingest_document(&format!(
            "{BASE}/control/CVE-2024-6602_no-notaffected.json.xz"
        ))
        .await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    extract_for_sbom(ctx, sbom_id).await?;
    assert!(load_evidence(ctx, sbom_id).await?.is_empty());
    extract_for_advisory(ctx, Uuid::parse_str(&advisory.id)?).await?;
    assert!(load_evidence(ctx, sbom_id).await?.is_empty());
    Ok(())
}

/// The distinct factors of the confidences of an SBOM's evidence, by node and type. Evidence of
/// several original PURLs of the same statement has the same factors.
async fn factors_of(
    ctx: &TrustifyContext,
    sbom_id: Uuid,
) -> anyhow::Result<Vec<(String, String, f64, Vec<ConfidenceFactor>)>> {
    let mut result = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .order_by_asc(correlation_evidence::Column::NodeId)
        .order_by_asc(correlation_evidence::Column::Extractor)
        .all(&ctx.db)
        .await?
        .into_iter()
        .map(|e| {
            Ok((
                e.node_id,
                e.extractor,
                e.confidence,
                serde_json::from_value(e.confidence_factors)?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    result.dedup();
    Ok(result)
}

/// The confidence of a match is the product of its factors: the RPM stream, the rule deriving
/// the range, the default status, and the product.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn confidence_factors(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // an el8 package below an el8_7 fix, in RHEL 8 by its `distro=` qualifier
    let sbom = ctx.ingest_document(S5_SBOM).await?;
    ctx.ingest_document(S5_VEX).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    extract_for_sbom(ctx, sbom_id).await?;
    assert_eq!(
        factors_of(ctx, sbom_id).await?,
        vec![(
            "pkg-openssl".to_string(),
            FIXED_AS_FIRST_FIXED_BEFORE.to_string(),
            0.55,
            vec![
                ConfidenceFactor::new(
                    ConfidenceReason::RpmStream {
                        stream: StreamRelation::Major
                    },
                    0.8
                ),
                ConfidenceFactor::new(
                    ConfidenceReason::Rule {
                        rule: FIXED_AS_FIRST_FIXED_BEFORE.into()
                    },
                    0.9
                ),
                ConfidenceFactor::new(
                    ConfidenceReason::ProductConfirmed {
                        source: ApiContextSource::PurlQualifier,
                        distance: 0,
                        source_factor: Some(0.85),
                        wildcard_factor: Some(0.9),
                    },
                    0.77
                ),
            ]
        )]
    );

    // a CVE record's default status
    const BASE: &str = "scenarios/S25_cve_package_url";
    ctx.ingest_document(&format!("{BASE}/cve/CVE-2026-2950.json"))
        .await?;
    let sbom = ctx
        .ingest_document(&format!("{BASE}/sbom_lodash_4.17.21.cdx.json"))
        .await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    extract_for_sbom(ctx, sbom_id).await?;
    assert_eq!(
        factors_of(ctx, sbom_id).await?,
        vec![(
            "pkg-lodash".to_string(),
            DEFAULT.to_string(),
            0.9,
            vec![
                ConfidenceFactor::new(ConfidenceReason::Purl, 1.0),
                ConfidenceFactor::new(ConfidenceReason::DefaultStatus, 0.9),
            ]
        )]
    );

    Ok(())
}

/// Batches of any size match like a single batch: each target's rows stay together, including
/// identifiers sharing a versioned PURL with different qualifiers.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn batches_match_like_a_single_batch(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom_id = Uuid::parse_str(&ctx.ingest_document(S5_SBOM).await?.id)?;
    ctx.ingest_document(S5_VEX).await?;
    let tx = ctx.db.begin().await?;
    let mut identifiers = PurlExtractor
        .sbom_identifiers(sbom_id, None, &tx)
        .await?
        .into_iter()
        .map(|node| vec![node.identifier])
        .collect::<Vec<_>>();
    identifiers.extend([
        vec![IdentifierRef {
            kind: IdentifierKind::Purl,
            value: "pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=x86_64&epoch=1".into(),
        }],
        vec![IdentifierRef {
            kind: IdentifierKind::Purl,
            value: "pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=aarch64&epoch=1".into(),
        }],
    ]);
    let sorted = |mut matches: Vec<ComponentMatch>| {
        matches.sort_by_cached_key(|m| format!("{m:?}"));
        matches
    };
    let batched = async |components: &[Vec<IdentifierRef>], batch_size| {
        let mut matches = CollectMatches::default();
        match_batched(components, batch_size, &mut matches, &tx)
            .await
            .map(|()| matches.0)
    };
    let single = sorted(batched(&identifiers, usize::MAX).await?);
    assert!(single.iter().any(|m| m.component == identifiers.len() - 1));
    for batch_size in [1, 2] {
        assert_eq!(
            sorted(batched(&identifiers, batch_size).await?),
            single,
            "batch size {batch_size}"
        );
    }
    assert_eq!(batched(&[], 1).await?, Vec::<ComponentMatch>::new());
    Ok(())
}

/// Collects the parts as they are handed over.
#[derive(Default)]
struct Parts(Vec<MatchPart>);

#[async_trait::async_trait]
impl MatchSink for Parts {
    async fn accept(&mut self, part: MatchPart) -> Result<(), Error> {
        self.0.push(part);
        Ok(())
    }
}

/// Each part has all matches of its components, so a component is in a single part, and together
/// the parts are the matches of `match_identifiers`.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn parts_hold_all_matches_of_their_components(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom_id = Uuid::parse_str(&ctx.ingest_document(S5_SBOM).await?.id)?;
    ctx.ingest_documents([S5_VEX, S9_VEX]).await?;
    let tx = ctx.db.begin().await?;
    let mut components = PurlExtractor
        .sbom_identifiers(sbom_id, None, &tx)
        .await?
        .into_iter()
        .map(|node| vec![node.identifier])
        .collect::<Vec<_>>();
    // two components with the same PURL share a part
    components.push(components[0].clone());

    let mut parts = Parts::default();
    PurlExtractor
        .match_parts(&components, &mut parts, &tx)
        .await?;

    // only openssl matches, in one part for both of its components
    assert_eq!(
        parts
            .0
            .iter()
            .map(|part| part.components.clone())
            .collect::<Vec<_>>(),
        vec![vec![0, components.len() - 1]]
    );

    let mut expanded = CollectMatches::default();
    for part in parts.0 {
        expanded.accept(part).await?;
    }
    let sorted = |mut matches: Vec<ComponentMatch>| {
        matches.sort_by_cached_key(|m| format!("{m:?}"));
        matches
    };
    assert_eq!(
        sorted(expanded.0),
        sorted(PurlExtractor.match_identifiers(&components, &tx).await?)
    );
    Ok(())
}

/// RPM versions for comparing the SQL stream functions with the Rust ones.
const RPM_VERSIONS: &[&str] = &[
    "1:1.1.1k-9.el8_6",
    "1.1.1k-9.el8_6",
    "1.1.1k-7.el8",
    "1.1.1k",
    "1.0-1.module+el8.4.0+123+abc",
    "2.4-1.fc39",
    "2.4-1.fc39.1",
    "1.0-2.amzn2",
    "1.0-rc1-2.el9",
    "x:1.0-1",
    "+1:1.0-1.el9",
    "99999999999:1.0-1.el9",
    "5.14.0-427.13.1.el9_4",
    "3.0.7-1.el9",
    "3.1.4-150600.5.39.1",
    "1.0-lp155.2.1",
    "1.0-a.b1.el7",
    "1.0-1",
    "1.0",
    "-",
    "",
];

/// The SQL stream functions agree with the Rust ones, so the SQL pre-filter of other streams
/// never drops a range which [`Ecosystem::stream_match`] keeps.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn sql_streams_agree_with_rust(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let tx = ctx.db.begin().await?;
    let query = |select: &mut SelectStatement| {
        let (sql, values) = select.build(PostgresQueryBuilder);
        Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
    };
    for version in RPM_VERSIONS {
        let row = tx
            .query_one_raw(query(
                Query::select()
                    .expr(Func::cust("rpm_stream").arg(*version))
                    .expr(Func::cust("rpm_stream_major").arg(SimpleExpr::FunctionCall(
                        Func::cust("rpm_stream").arg(*version),
                    ))),
            ))
            .await?
            .ok_or_else(|| anyhow::anyhow!("no row"))?;
        let stream = Evr::parse(version).stream();
        assert_eq!(
            (
                row.try_get_by_index::<Option<String>>(0)?,
                row.try_get_by_index::<Option<String>>(1)?
            ),
            (
                stream.map(str::to_string),
                stream.map(|stream| stream_major(stream).to_string())
            ),
            "{version}"
        );
    }
    for sbom in RPM_VERSIONS {
        for range in RPM_VERSIONS {
            let row = tx
                .query_one_raw(query(Query::select().expr(ecosystem::rpm::other_stream(
                    Expr::val(*sbom),
                    Expr::val(*range),
                ))))
                .await?
                .ok_or_else(|| anyhow::anyhow!("no row"))?;
            assert_eq!(
                row.try_get_by_index::<bool>(0)?,
                ecosystem::rpm::stream_match(sbom, Some(range)).is_none(),
                "{sbom} / {range}"
            );
        }
    }
    for (ty, namespace) in [
        ("rpm", Some("redhat")),
        ("rpm", None),
        ("rpm", Some("suse")),
        ("deb", Some("debian")),
        ("npm", None),
    ] {
        let row = tx
            .query_one_raw(query(
                Query::select().expr(Ecosystem::is_rpm(Expr::val(ty), Expr::val(namespace))),
            ))
            .await?
            .ok_or_else(|| anyhow::anyhow!("no row"))?;
        assert_eq!(
            row.try_get_by_index::<bool>(0)?,
            Ecosystem::of(ty, namespace) == Ecosystem::Rpm,
            "{ty} {namespace:?}"
        );
    }
    Ok(())
}

/// The matched rows of an advisory, as [`load_advisory_purl_matches`] reads them.
async fn advisory_rows<'a>(
    advisory_id: Uuid,
    sources: &[(Source<'a>, Candidates)],
    tx: &DatabaseTransaction,
) -> anyhow::Result<Vec<(NodeRef, Source<'a>, PurlStatusRow)>> {
    let (query, values) = purl_status_matches(&Scope::Advisory(advisory_id), sources)
        .ok_or_else(|| anyhow::anyhow!("no statement"))?
        .build(PostgresQueryBuilder);
    let stated = load_stated(
        Expr::col((purl_status::Entity, purl_status::Column::AdvisoryId)).eq(advisory_id),
        tx,
    )
    .await?;
    let rows = AdvisoryPurlMatch::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        query,
        values,
    ))
    .all(tx)
    .await?
    .into_iter()
    .map(|row| {
        let node = NodeRef {
            sbom_id: row.sbom_id,
            node_id: row.node_id,
        };
        let source = source_of(sources, row.matched.source)?;
        Ok(row
            .matched
            .into_rows(&stated, &row.sbom_qualifiers)
            .into_iter()
            .map(|status| (node.clone(), source, status))
            .collect::<Vec<_>>())
    })
    .collect::<Result<Vec<_>, Error>>()?
    .into_iter()
    .flatten()
    .collect();
    Ok(rows)
}

fn sorted_matches(mut matches: Vec<NodeMatch>) -> Vec<NodeMatch> {
    matches.sort_by_cached_key(|m| format!("{m:?}"));
    matches
}

/// Assert that the matches of an advisory don't depend on the order of their rows, which the
/// statement doesn't define within a node.
pub(crate) async fn assert_independent_of_row_order(
    advisory_id: Uuid,
    tx: &DatabaseTransaction,
) -> anyhow::Result<()> {
    let rules = rules(tx).await?;
    let sources = sources(&rules).collect::<Vec<_>>();
    let rows = advisory_rows(advisory_id, &sources, tx).await?;
    let matches = |rows: Vec<_>| {
        sorted_matches(
            group(rows)
                .map(|(node, assertion)| NodeMatch { node, assertion })
                .collect(),
        )
    };
    let mut reversed = rows.clone();
    reversed.reverse();
    let mut rotated = rows.clone();
    rotated.rotate_left(rows.len() / 2);
    let (even, odd): (Vec<_>, Vec<_>) = rows
        .iter()
        .cloned()
        .enumerate()
        .partition(|(index, _)| index % 2 == 0);
    let interleaved = odd.into_iter().chain(even).map(|(_, row)| row).collect();

    let expected = matches(rows);
    assert_eq!(matches(reversed), expected);
    assert_eq!(matches(rotated), expected);
    assert_eq!(matches(interleaved), expected);
    Ok(())
}

const BUILDAH_SBOM: &str = "correlation/buildah_el9_4.cdx.json";
const BUILDAH_VEX: &str = "correlation/cve-2024-34155.json.xz";

/// A PURL without a version has no version to compare, so a statement without versions doesn't
/// match it, in either direction.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn versionless_purl_matches_nothing(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("correlation/versionless_okhttp.cdx.json")
        .await?;
    let advisory = ctx
        .ingest_document("correlation/cve-2025-27148.json")
        .await?;

    let tx = ctx.db.begin().await?;
    let matches = PurlExtractor
        .match_advisory(Uuid::parse_str(&advisory.id)?, &tx)
        .await?;

    assert_eq!(matches, vec![]);
    Ok(())
}

/// The fixes of one package state ranges of several streams under one rule, here a module build
/// without a stream and `el9_4`. Only the own stream's applies without a context, and the result
/// doesn't depend on the order of the rows.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_streams_of_any_row_order(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document(BUILDAH_SBOM).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let advisory_id = Uuid::parse_str(&ctx.ingest_document(BUILDAH_VEX).await?.id)?;
    // Rows without their PURL and product, as stored by earlier versions: the module build isn't
    // filtered by its `rpmmod` qualifier, and is merged with the package's other fixes.
    ctx.db
        .execute_raw(sql(
            "UPDATE purl_status SET qualified_purl_id = NULL, assertion_context_id = NULL \
             WHERE advisory_id = $1",
            vec![advisory_id.into()],
        ))
        .await?;

    let tx = ctx.db.begin().await?;
    let rules = rules(&tx).await?;
    let sources = sources(&rules).collect::<Vec<_>>();
    let rows = advisory_rows(advisory_id, &sources, &tx).await?;
    assert!(rows.len() > 1);
    let matches = |rows: Vec<_>| {
        sorted_matches(
            group(rows)
                .map(|(node, assertion)| NodeMatch { node, assertion })
                .collect(),
        )
    };
    let mut reversed = rows.clone();
    reversed.reverse();
    assert_eq!(matches(rows), matches(reversed));
    tx.rollback().await?;

    let expected = vec![(
        "pkg-buildah".to_string(),
        "CVE-2024-34155".to_string(),
        FIXED_AS_FIRST_FIXED_BEFORE.to_string(),
        AssertionStatus::Affected,
        0.9,
        Some(MatchedValue {
            source_provider: None,
            origin: AssertionOrigin::PublisherPolicy,
            identifier: "pkg:rpm/redhat/buildah".into(),
            // an omitted epoch is zero, so this version is below the fix of epoch 2
            ranges: fixed_in("rpm", &["2:1.33.9-1.el9_4"]),
            enabled_by: Some(redhat_first_fixed()),
        }),
    )];
    extract_for_sbom(ctx, sbom_id).await?;
    assert_eq!(range_evidence(ctx, sbom_id).await?, expected);

    correlation_evidence::Entity::delete_many()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .exec(&ctx.db)
        .await?;
    extract_for_advisory(ctx, advisory_id).await?;
    assert_eq!(range_evidence(ctx, sbom_id).await?, expected);
    Ok(())
}

/// Grouping the advisory's rows per node while reading them gives the same matches as grouping
/// all rows at once, also with several SBOMs sharing versions and node IDs.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn advisory_rows_group_per_node(ctx: &TrustifyContext) -> anyhow::Result<()> {
    for sbom in [
        S5_SBOM,
        "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.spdx.json",
        "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_at-fix.cdx.json",
        "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_at-fix.spdx.json",
    ] {
        ctx.ingest_document(sbom).await?;
    }
    let advisory_id = Uuid::parse_str(&ctx.ingest_document(S5_VEX).await?.id)?;
    let tx = ctx.db.begin().await?;
    let rules = rules(&tx).await?;
    let sources = sources(&rules).collect::<Vec<_>>();
    let rows = advisory_rows(advisory_id, &sources, &tx).await?;
    let at_once = sorted_matches(
        group(rows)
            .map(|(node, assertion)| NodeMatch { node, assertion })
            .collect(),
    );
    assert!(
        at_once
            .iter()
            .map(|m| m.node.sbom_id)
            .collect::<BTreeSet<_>>()
            .len()
            > 1
    );
    assert_eq!(
        sorted_matches(load_advisory_purl_matches(advisory_id, &sources, &tx).await?),
        at_once
    );
    Ok(())
}
