use crate::service::CorrelationService;
use sea_orm::{ActiveModelTrait, Set};
use test_context::test_context;
use test_log::test;
use trustify_entity::correlation_evidence::{self, AssertionStatus, MatchDimension};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn empty_sbom_returns_no_verdicts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = CorrelationService;
    let result = service.correlate_sbom(Uuid::new_v4(), &ctx.db).await?;
    assert!(result.verdicts.is_empty());
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
        match_dimension: Set(MatchDimension::Digest),
        confidence: Set(0.95),
        extractor: Set("digest".to_string()),
        created_at: Set(time::OffsetDateTime::now_utc()),
    };
    evidence.insert(&ctx.db).await?;

    let service = CorrelationService;
    let result = service.correlate_sbom(sbom_id, &ctx.db).await?;

    assert_eq!(result.verdicts.len(), 1);
    let verdict = &result.verdicts[0];
    assert_eq!(verdict.vulnerability.id, "CVE-2023-33201");
    assert_eq!(verdict.status, crate::model::VerdictStatus::Affected);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].extractor, "digest");

    Ok(())
}
