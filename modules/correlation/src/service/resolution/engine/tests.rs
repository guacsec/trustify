use super::*;

fn evidence(
    id: &str,
    status: ApiAssertionStatus,
    confidence: f64,
    origin: AssertionOrigin,
    provider: Option<&str>,
) -> DecisionEvidence {
    DecisionEvidence {
        reference: id.into(),
        advisory_id: Uuid::nil(),
        status,
        confidence,
        value: Some(MatchedValue {
            origin,
            ..MatchedValue::new("pkg:generic/example@1")
        }),
        provider: ProviderIdentity {
            identifiers: provider
                .map(|p| vec![format!("namespace:{p}")])
                .unwrap_or_default(),
            ..Default::default()
        },
        contexts: vec![],
        factors: vec![],
        remediations: vec![],
    }
}
fn component() -> ProviderResolution {
    ProviderResolution {
        provider: Some("A".into()),
        identifiers: vec!["name:Acme".into()],
        ..Default::default()
    }
}
fn decision(input: &[DecisionEvidence]) -> Decision {
    resolve(input, component(), &ResolutionContext::default(), true).unwrap()
}
fn check_pair(first: DecisionEvidence, second: DecisionEvidence, criterion: SelectionReason) {
    let result = decision(&[second.clone(), first.clone()]);
    assert_eq!(result.summary.confidence, first.confidence);
    assert!(result.summary.has_conflict);
    let trace = result.summary.explanation.as_ref().unwrap();
    assert_eq!(
        trace.winning_evidence.as_deref(),
        Some(first.reference.as_str())
    );
    assert_eq!(
        trace.opposing_evidence.as_deref(),
        Some(second.reference.as_str())
    );
    assert_eq!(trace.deciding_criterion, criterion);
    assert_eq!(trace.evidence[0].outcome, EvidenceOutcome::Selected);
    assert_eq!(trace.evidence[1].outcome, EvidenceOutcome::Conflicting);
    assert_eq!(trace.evidence[1].selection_reason, criterion);
    // Input order and duplicate assertions cannot affect the decision or trace.
    assert_eq!(
        result,
        decision(&[first.clone(), second.clone(), first, second])
    );
}

#[test]
fn each_criterion_takes_precedence_over_all_later_criteria() {
    use ApiAssertionStatus::{Affected, Fixed};
    use AssertionOrigin::{Inferred, Stated};
    check_pair(
        evidence("a", Fixed, 0.01, Inferred, Some("A")),
        evidence("b", Affected, 1.0, Stated, None),
        SelectionReason::ProviderRelationship,
    );
    check_pair(
        evidence("a", Affected, 0.01, Stated, Some("A")),
        evidence("b", Fixed, 1.0, Inferred, Some("A")),
        SelectionReason::AssertionOrigin,
    );
    check_pair(
        evidence("a", Fixed, 0.9, Stated, Some("A")),
        evidence("b", Affected, 0.8, Stated, Some("A")),
        SelectionReason::MatchConfidence,
    );
    check_pair(
        evidence("a", Affected, 0.8, Stated, Some("A")),
        evidence("b", Fixed, 0.8, Stated, Some("A")),
        SelectionReason::StatusPriority,
    );
}

#[test]
fn provider_tiers_include_names_and_distinguish_lost_attribution() {
    use ApiAssertionStatus::{Affected, Fixed};
    use AssertionOrigin::Stated;
    let mut named = evidence("named", Fixed, 0.1, Stated, None);
    named.provider.identifiers = vec!["name:Organization: ACME ".into()];
    let matching = evidence("matching", Affected, 0.01, Stated, Some("A"));
    let generic = evidence("generic", Affected, 1.0, Stated, None);
    check_pair(
        matching,
        named.clone(),
        SelectionReason::ProviderRelationship,
    );
    check_pair(
        named,
        generic.clone(),
        SelectionReason::ProviderRelationship,
    );
    check_pair(
        generic.clone(),
        evidence("other", Fixed, 1.0, Stated, Some("B")),
        SelectionReason::ProviderRelationship,
    );
    let mut lost = evidence("lost", Fixed, 1.0, Stated, None);
    lost.provider.unavailable = true;
    check_pair(generic, lost.clone(), SelectionReason::ProviderRelationship);
    let result = decision(&[lost]);
    let trace = result.summary.explanation.unwrap();
    assert_eq!(
        trace.evidence[0].provider_relationship,
        ProviderRelationship::Other
    );
    assert!(!trace.evidence[0].provider.diagnostics.is_empty());
}

#[test]
fn resolved_providers_do_not_match_by_name() {
    let other = ProviderResolution {
        provider: Some("B".into()),
        identifiers: vec!["name:Acme".into()],
        ..Default::default()
    };
    assert_eq!(provider_match(&component(), &other), None);
}

#[test]
fn direct_defaults_beat_inference_and_unknown_origins() {
    for origin in [
        AssertionOrigin::Inferred,
        AssertionOrigin::PublisherPolicy,
        AssertionOrigin::Unknown,
    ] {
        for direct in [AssertionOrigin::Stated, AssertionOrigin::Default] {
            check_pair(
                evidence("direct", ApiAssertionStatus::Affected, 0.2, direct, None),
                evidence("indirect", ApiAssertionStatus::Fixed, 1.0, origin, None),
                SelectionReason::AssertionOrigin,
            );
        }
    }
}

#[test]
fn status_priority_and_stable_reference() {
    let statuses = [
        ApiAssertionStatus::Affected,
        ApiAssertionStatus::Fixed,
        ApiAssertionStatus::NotAffected,
        ApiAssertionStatus::UnderInvestigation,
    ];
    for (index, preferred) in statuses.iter().enumerate() {
        for other in &statuses[index + 1..] {
            check_pair(
                evidence("a", *preferred, 1.0, AssertionOrigin::Stated, None),
                evidence("b", *other, 1.0, AssertionOrigin::Stated, None),
                SelectionReason::StatusPriority,
            );
        }
    }
    let a = evidence(
        "a",
        ApiAssertionStatus::Fixed,
        0.8,
        AssertionOrigin::Stated,
        None,
    );
    let mut b = a.clone();
    b.reference = "b".into();
    let result = decision(&[b, a]);
    assert!(!result.summary.has_conflict);
    let trace = result.summary.explanation.unwrap();
    assert_eq!(trace.winning_evidence.as_deref(), Some("a"));
    assert_eq!(trace.deciding_criterion, SelectionReason::EvidenceReference);
    assert_eq!(trace.evidence[1].outcome, EvidenceOutcome::Supporting);
}

#[test]
fn nonvoting_evidence_and_empty_input() {
    let recommended = evidence(
        "recommended",
        ApiAssertionStatus::Recommended,
        1.0,
        AssertionOrigin::Stated,
        Some("A"),
    );
    let zero = evidence(
        "zero",
        ApiAssertionStatus::Affected,
        0.0,
        AssertionOrigin::Stated,
        Some("A"),
    );
    for input in [vec![], vec![recommended.clone()], vec![recommended, zero]] {
        let result = decision(&input);
        assert_eq!(result.status, VerdictStatus::None);
        assert_eq!(result.summary.confidence, 0.0);
        assert!(!result.summary.has_conflict);
        let trace = result.summary.explanation.unwrap();
        assert_eq!(
            trace.deciding_criterion,
            SelectionReason::NoEligibleEvidence
        );
        assert!(trace.winning_evidence.is_none());
        assert!(
            trace
                .evidence
                .iter()
                .all(|e| e.outcome == EvidenceOutcome::NonVoting)
        );
    }
    let eligible = evidence(
        "tiny",
        ApiAssertionStatus::Fixed,
        1e-12,
        AssertionOrigin::Unknown,
        None,
    );
    assert_eq!(decision(&[eligible]).summary.confidence, 1e-12);
}

#[test]
fn invalid_confidence_is_rejected() {
    for confidence in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1, 1.1] {
        let input = evidence(
            "bad",
            ApiAssertionStatus::Affected,
            confidence,
            AssertionOrigin::Stated,
            None,
        );
        assert!(resolve(&[input], component(), &ResolutionContext::default(), false).is_err());
    }
}

#[test]
fn explanation_is_optional_and_does_not_change_resolution() {
    let input = [
        evidence(
            "fixed",
            ApiAssertionStatus::Fixed,
            0.8,
            AssertionOrigin::Stated,
            None,
        ),
        evidence(
            "affected",
            ApiAssertionStatus::Affected,
            0.7,
            AssertionOrigin::Stated,
            None,
        ),
    ];
    let mut explained = decision(&input);
    let plain = resolve(&input, component(), &ResolutionContext::default(), false).unwrap();
    assert!(explained.summary.explanation.take().is_some());
    assert_eq!(explained, plain);
    assert_eq!(plain.summary.confidence, 0.8);
}

#[test]
fn fingerprint_tracks_aliases_and_context_but_not_explanation_flag() {
    let mut request = ResolutionRequest::default();
    let initial = ResolutionContext::new(vec![], &request)
        .unwrap()
        .revision(&component());
    request.include_explanation = true;
    assert_eq!(
        initial,
        ResolutionContext::new(vec![], &request)
            .unwrap()
            .revision(&component())
    );
    request.component_provider = Some(" B/ ".into());
    let context = ResolutionContext::new(vec![], &request).unwrap();
    assert_eq!(context.component_provider.as_deref(), Some("B"));
    assert_ne!(initial, context.revision(&component()));
    let mut aliases = vec![
        ProviderAlias {
            id: Uuid::from_u128(1),
            revision: Uuid::nil(),
            data: ProviderAliasData {
                provider: "A".into(),
                aliases: vec!["name:acme".into()],
            },
        },
        ProviderAlias {
            id: Uuid::from_u128(2),
            revision: Uuid::nil(),
            data: ProviderAliasData {
                provider: "B".into(),
                aliases: vec!["name:other".into()],
            },
        },
    ];
    let revision = ResolutionContext::new(aliases.clone(), &request)
        .unwrap()
        .revision(&component());
    assert_ne!(revision, context.revision(&component()));
    aliases.reverse();
    assert_eq!(
        revision,
        ResolutionContext::new(aliases, &request)
            .unwrap()
            .revision(&component())
    );
    request.component_provider = Some(" / ".into());
    assert!(ResolutionContext::new(vec![], &request).is_err());
}
