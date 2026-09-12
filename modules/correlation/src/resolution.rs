//! Deterministic resolution of matching assertions into verdicts.

use crate::{
    engine::Collector,
    matching::{check_version, match_dimension, match_evidence, version_constraint},
    options::CorrelationOptions,
    types::{
        AssertionRef, ComponentMatcher, ComponentQuery, MatchSpecificity, ResolutionRule,
        StatusAssertion, TraceEntry, Verdict, VerdictStatus,
    },
};

pub(crate) fn resolve_verdict(
    component: &ComponentQuery,
    vuln_id: &str,
    assertions: &[&StatusAssertion],
    options: &CorrelationOptions,
    collector: &mut dyn Collector,
) -> Verdict {
    let applicable: Vec<_> = assertions
        .iter()
        .copied()
        .filter(|assertion| check_version(&component.id, assertion, options))
        .collect();
    let mut ordered = applicable;
    ordered.sort_by(assertion_order);

    let mut contributing = Vec::new();
    let mut evidence = Vec::new();
    for assertion in &ordered {
        contributing.push(AssertionRef {
            source: assertion.source.clone(),
            status: assertion.status,
            matched_by: match_dimension(&assertion.matcher),
            matcher: assertion.matcher.clone(),
            version_constraint: version_constraint(&assertion.matcher),
            version_in_range: Some(true),
            context: assertion.context.clone(),
        });
    }
    for assertion in assertions {
        let version_in_range = check_version(&component.id, assertion, options);
        evidence.push(match_evidence(&component.id, assertion, version_in_range));
    }

    let strongest_dimension = ordered
        .iter()
        .map(|assertion| matcher_specificity(&assertion.matcher))
        .max();
    let relevant: Vec<_> = ordered
        .iter()
        .filter(|assertion| {
            strongest_dimension
                .is_none_or(|specificity| matcher_specificity(&assertion.matcher) == specificity)
        })
        .filter(|assertion| {
            !matches!(
                options.product_matches,
                crate::options::ProductMatchPolicy::EvidenceOnly
            ) || !matches!(assertion.matcher, ComponentMatcher::CveProduct { .. })
        })
        .collect();

    let has_affected = relevant
        .iter()
        .any(|assertion| assertion.status == crate::types::AssertionStatus::Affected);
    let has_resolution = relevant
        .iter()
        .any(|assertion| assertion.status.resolves_affected());
    let all_cpe_only = !relevant.is_empty()
        && relevant
            .iter()
            .all(|assertion| matches!(assertion.matcher, ComponentMatcher::CpeMatch { .. }));
    let (final_status, rule) = if ordered.is_empty() {
        (VerdictStatus::None, ResolutionRule::NoApplicableAssertion)
    } else if all_cpe_only
        && has_affected
        && matches!(
            options.resolution,
            crate::options::ResolutionPolicy::Conservative
        )
    {
        (VerdictStatus::Affected, ResolutionRule::CpeAffectedWins)
    } else if has_resolution {
        let status = relevant
            .iter()
            .filter(|assertion| assertion.status.resolves_affected())
            .max_by_key(|assertion| status_precedence(assertion.status))
            .map(|assertion| match assertion.status {
                crate::types::AssertionStatus::Fixed => VerdictStatus::Fixed,
                crate::types::AssertionStatus::NotAffected => VerdictStatus::NotAffected,
                _ => VerdictStatus::NotAffected,
            })
            .unwrap_or(VerdictStatus::NotAffected);
        (status, ResolutionRule::SpecificResolution)
    } else if has_affected {
        (VerdictStatus::Affected, ResolutionRule::AffectedOnly)
    } else {
        (
            VerdictStatus::UnderInvestigation,
            ResolutionRule::UnderInvestigationOnly,
        )
    };

    let contradictory = ordered
        .iter()
        .any(|assertion| assertion.status == crate::types::AssertionStatus::Affected)
        && ordered
            .iter()
            .any(|assertion| assertion.status.resolves_affected());
    let confidence = crate::confidence::assess(&evidence, contradictory);

    let reason = match rule {
        ResolutionRule::NoApplicableAssertion => "no applicable assertion",
        ResolutionRule::CpeAffectedWins => "CPE-only match: affected wins at product level",
        ResolutionRule::SpecificResolution => {
            "most specific resolution (fixed/not_affected) overrides affected"
        }
        ResolutionRule::AffectedOnly => "only affected assertions matched",
        ResolutionRule::UnderInvestigationOnly => "only non-definitive assertions matched",
    };

    if options.trace.enabled {
        collector.on_trace(&TraceEntry {
            message: format!(
                "  VERDICT {vuln_id} = {} ({} contributing assertions)",
                final_status.as_str(),
                ordered.len(),
            ),
            detail: Some(format!("{}; {}", reason, confidence.explanation())),
        });
    }

    Verdict {
        component: component.id.clone(),
        context: component.context.clone(),
        vulnerability_id: vuln_id.to_string(),
        status: final_status,
        contributing_assertions: contributing,
        evidence,
        resolution_rule: rule,
        confidence,
    }
}

fn matcher_specificity(matcher: &ComponentMatcher) -> MatchSpecificity {
    match matcher {
        ComponentMatcher::Purl { qualifiers, .. } if !qualifiers.is_empty() => {
            MatchSpecificity::QualifiedPurl
        }
        ComponentMatcher::Purl { .. } => MatchSpecificity::Purl,
        ComponentMatcher::Hash { .. } => MatchSpecificity::Hash,
        ComponentMatcher::CpeMatch { .. } => MatchSpecificity::Cpe,
        ComponentMatcher::CveProduct { .. } => MatchSpecificity::Product,
    }
}

fn assertion_order(left: &&StatusAssertion, right: &&StatusAssertion) -> std::cmp::Ordering {
    // Descending: strongest identity evidence first, then most decisive status.
    // Remaining ties fall back to a stable, allocation-free source ordering;
    // `sort_by` is stable, so assertions equal under these keys keep their
    // (deterministic) extraction order. Ordering only affects the presentation
    // order of `contributing_assertions`/`evidence`, not the resolved status.
    matcher_specificity(&right.matcher)
        .cmp(&matcher_specificity(&left.matcher))
        .then_with(|| status_precedence(right.status).cmp(&status_precedence(left.status)))
        .then_with(|| right.source.identifier.cmp(&left.source.identifier))
        .then_with(|| right.source.source_file.cmp(&left.source.source_file))
}

fn status_precedence(status: crate::types::AssertionStatus) -> u8 {
    match status {
        crate::types::AssertionStatus::Fixed => 3,
        crate::types::AssertionStatus::NotAffected => 2,
        crate::types::AssertionStatus::Affected => 1,
        crate::types::AssertionStatus::UnderInvestigation => 0,
        crate::types::AssertionStatus::Recommended => 0,
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{ResolutionRule, VerdictStatus};

    #[test]
    fn verdict_status_has_explicit_none() {
        assert_eq!(VerdictStatus::None.as_str(), "none");
        assert_eq!(
            ResolutionRule::NoApplicableAssertion,
            ResolutionRule::NoApplicableAssertion
        );
    }
}
