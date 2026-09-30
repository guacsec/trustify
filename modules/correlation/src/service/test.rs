use crate::service::CorrelationService;
use sea_orm::{ActiveModelTrait, Set};
use test_context::test_context;
use test_log::test;
use trustify_entity::correlation_evidence::{self, AssertionStatus};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn empty_sbom_returns_no_verdicts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = CorrelationService;
    let result = service
        .correlate_sbom(Uuid::new_v4(), false, &ctx.db)
        .await?;
    assert!(result.verdicts.is_empty());
    assert!(result.unmatched_components.is_none());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn evidence_produces_verdict(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let advisory = ctx.ingest_document("csaf/CVE-2023-33201.json").await?;

    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;

    let evidence = correlation_evidence::ActiveModel {
        id: Set(Uuid::new_v4()),
        sbom_id: Set(sbom_id),
        node_id: Set("SPDXRef-Package".to_string()),
        advisory_id: Set(advisory_id),
        vulnerability_id: Set("CVE-2023-33201".to_string()),
        status: Set(AssertionStatus::Affected),

        confidence: Set(0.95),
        extractor: Set("digest".to_string()),
        matched_value: Set(None),
        created_at: Set(time::OffsetDateTime::now_utc()),
    };
    evidence.insert(&ctx.db).await?;

    let service = CorrelationService;
    let result = service.correlate_sbom(sbom_id, false, &ctx.db).await?;

    assert_eq!(result.verdicts.len(), 1);
    let verdict = &result.verdicts[0];
    assert_eq!(verdict.vulnerability.id, "CVE-2023-33201");
    assert_eq!(verdict.status, crate::model::VerdictStatus::Affected);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].extractor, "digest");
    assert!(result.unmatched_components.is_none());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn include_unmatched_returns_components_without_evidence(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let advisory = ctx.ingest_document("csaf/CVE-2023-33201.json").await?;

    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;

    let evidence = correlation_evidence::ActiveModel {
        id: Set(Uuid::new_v4()),
        sbom_id: Set(sbom_id),
        node_id: Set("SPDXRef-A".to_string()),
        advisory_id: Set(advisory_id),
        vulnerability_id: Set("CVE-2023-33201".to_string()),
        status: Set(AssertionStatus::Affected),

        confidence: Set(0.9),
        extractor: Set("digest".to_string()),
        matched_value: Set(None),
        created_at: Set(time::OffsetDateTime::now_utc()),
    };
    evidence.insert(&ctx.db).await?;

    let service = CorrelationService;
    let result = service.correlate_sbom(sbom_id, true, &ctx.db).await?;

    assert_eq!(result.verdicts.len(), 1);
    assert_eq!(result.verdicts[0].component.node_id, "SPDXRef-A");

    let unmatched = result
        .unmatched_components
        .as_ref()
        .expect("should be Some");
    assert!(
        !unmatched.is_empty(),
        "should contain components without evidence"
    );
    assert!(
        !unmatched.iter().any(|c| c.node_id == "SPDXRef-A"),
        "matched component should not appear in unmatched"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn include_unmatched_no_evidence_returns_all_components(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    let service = CorrelationService;
    let result = service.correlate_sbom(sbom_id, true, &ctx.db).await?;

    assert!(result.verdicts.is_empty());
    let unmatched = result
        .unmatched_components
        .as_ref()
        .expect("should be Some");
    assert!(
        !unmatched.is_empty(),
        "should contain all package components"
    );

    Ok(())
}
