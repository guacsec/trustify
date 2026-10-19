use super::provider::{ResolutionContext, provider_match};
use crate::{error::Error, model::*};
use std::cmp::Ordering;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct DecisionEvidence {
    pub reference: String,
    pub advisory_id: Uuid,
    pub status: ApiAssertionStatus,
    pub confidence: f64,
    pub value: Option<MatchedValue>,
    pub provider: ProviderIdentity,
    /// The products the evidence was matched in, only reported in the explanation.
    pub contexts: Vec<EvidenceContext>,
}

fn status(status: ApiAssertionStatus) -> Option<VerdictStatus> {
    match status {
        ApiAssertionStatus::Affected => Some(VerdictStatus::Affected),
        ApiAssertionStatus::Fixed => Some(VerdictStatus::Fixed),
        ApiAssertionStatus::NotAffected => Some(VerdictStatus::NotAffected),
        ApiAssertionStatus::UnderInvestigation => Some(VerdictStatus::UnderInvestigation),
        ApiAssertionStatus::Recommended => None,
    }
}

fn priority(status: VerdictStatus) -> u8 {
    match status {
        VerdictStatus::Affected => 0,
        VerdictStatus::Fixed => 1,
        VerdictStatus::NotAffected => 2,
        VerdictStatus::UnderInvestigation => 3,
        VerdictStatus::None => 4,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub status: VerdictStatus,
    pub summary: ResolutionSummary,
    pub winning_advisory: Option<Uuid>,
}

fn direct(origin: AssertionOrigin) -> bool {
    matches!(origin, AssertionOrigin::Stated | AssertionOrigin::Default)
}

fn eligible(e: &ResolutionEvidence) -> bool {
    status(e.status).is_some() && e.match_confidence > 0.0
}

/// Strongest evidence first. Later criteria cannot override earlier criteria.
fn compare(a: &ResolutionEvidence, b: &ResolutionEvidence) -> Ordering {
    eligible(b)
        .cmp(&eligible(a))
        .then(a.provider_relationship.cmp(&b.provider_relationship))
        .then(direct(b.assertion_origin).cmp(&direct(a.assertion_origin)))
        .then(b.match_confidence.total_cmp(&a.match_confidence))
        .then(
            priority(status(a.status).unwrap_or(VerdictStatus::None))
                .cmp(&priority(status(b.status).unwrap_or(VerdictStatus::None))),
        )
        .then(a.evidence_ref.cmp(&b.evidence_ref))
}

fn deciding_criterion(winner: &ResolutionEvidence, other: &ResolutionEvidence) -> SelectionReason {
    if winner.provider_relationship != other.provider_relationship {
        SelectionReason::ProviderRelationship
    } else if direct(winner.assertion_origin) != direct(other.assertion_origin) {
        SelectionReason::AssertionOrigin
    } else if winner.match_confidence != other.match_confidence {
        SelectionReason::MatchConfidence
    } else if winner.status != other.status {
        SelectionReason::StatusPriority
    } else {
        SelectionReason::EvidenceReference
    }
}

pub fn resolve(
    evidence: &[DecisionEvidence],
    component: ProviderResolution,
    context: &ResolutionContext,
    explain: bool,
) -> Result<Decision, Error> {
    let mut details = Vec::with_capacity(evidence.len());
    for e in evidence {
        if !e.confidence.is_finite() || !(0.0..=1.0).contains(&e.confidence) {
            return Err(Error::BadRequest(
                "Evidence match confidence must be finite and within [0, 1]".into(),
            ));
        }
        let provider = context.provider(&e.provider, "assertion source");
        let relationship = match provider_match(&component, &provider) {
            Some(ProviderMatch::Provider) => ProviderRelationship::MatchingProvider,
            Some(ProviderMatch::Name) => ProviderRelationship::MatchingName,
            None if e.provider.identifiers.is_empty() && !e.provider.unavailable => {
                ProviderRelationship::Providerless
            }
            None => ProviderRelationship::Other,
        };
        details.push(ResolutionEvidence {
            evidence_ref: e.reference.clone(),
            advisory_id: e.advisory_id,
            status: e.status,
            match_confidence: e.confidence,
            assertion_origin: e.value.as_ref().map(|v| v.origin).unwrap_or_default(),
            provider,
            provider_relationship: relationship,
            outcome: EvidenceOutcome::NonVoting,
            selection_reason: SelectionReason::NonVoting,
            contexts: e.contexts.clone(),
        });
    }
    details.sort_by(compare);
    details.dedup();
    let winner = details.first().filter(|e| eligible(e)).cloned();
    let opposition = winner
        .as_ref()
        .and_then(|w| details.iter().find(|e| eligible(e) && e.status != w.status))
        .cloned();
    let criterion = match &winner {
        None => SelectionReason::NoEligibleEvidence,
        Some(w) => opposition
            .as_ref()
            .or_else(|| details.get(1).filter(|e| eligible(e)))
            .map(|e| deciding_criterion(w, e))
            .unwrap_or(SelectionReason::OnlyEligibleEvidence),
    };
    let verdict = winner
        .as_ref()
        .and_then(|e| status(e.status))
        .unwrap_or(VerdictStatus::None);
    let confidence = winner.as_ref().map(|e| e.match_confidence).unwrap_or(0.0);
    let winning_advisory = winner.as_ref().map(|e| e.advisory_id);
    let has_conflict = opposition.is_some();
    let explanation = explain.then(|| {
        for e in &mut details {
            if let Some(w) = &winner
                && eligible(e)
            {
                if e.evidence_ref == w.evidence_ref {
                    e.outcome = EvidenceOutcome::Selected;
                    e.selection_reason = criterion;
                } else {
                    e.outcome = if e.status == w.status {
                        EvidenceOutcome::Supporting
                    } else {
                        EvidenceOutcome::Conflicting
                    };
                    e.selection_reason = deciding_criterion(w, e);
                }
            }
        }
        ResolutionExplanation {
            status: verdict,
            resolution_revision: context.revision(&component),
            component_provider: component,
            evidence: details,
            winning_evidence: winner.map(|e| e.evidence_ref),
            opposing_evidence: opposition.map(|e| e.evidence_ref),
            deciding_criterion: criterion,
            reason: criterion.label().into(),
        }
    });
    Ok(Decision {
        status: verdict,
        summary: ResolutionSummary {
            confidence,
            has_conflict,
            explanation,
        },
        winning_advisory,
    })
}

#[cfg(test)]
mod tests;
