//! Stateless evidence-to-verdict correlation and optional event observation.

use crate::{
    evidence::{AdvisoryEvidence, Evidence},
    matching::{self, format_component_id, format_matcher},
    resolution::resolve_verdict,
    types::{ComponentQuery, MatchEvidence, TraceEntry, Verdict},
};

/// Optional observer for correlation events as the engine processes them.
///
/// Correlation methods return owned verdicts directly. A collector is useful
/// for match evidence, traces, streaming, and metrics.
pub trait Collector {
    /// Called for each assertion that matched (or was checked against) a component.
    fn on_match(&mut self, evidence: &MatchEvidence);

    /// Called when the engine has resolved a final verdict for a component/vulnerability pair.
    fn on_verdict(&mut self, verdict: &Verdict);

    /// Called for each step in the decision trace.
    fn on_trace(&mut self, entry: &TraceEntry);
}

/// Resolve complete evidence into owned verdicts.
pub fn correlate(evidence: &Evidence, collector: &mut dyn Collector) -> Vec<Verdict> {
    verdicts_from_evidence(evidence, collector)
}

fn verdicts_from_evidence(evidence: &Evidence, collector: &mut dyn Collector) -> Vec<Verdict> {
    matching::queries_from_sbom(&evidence.sbom)
        .into_iter()
        .flat_map(|query| correlate_component_evidence(&query, &evidence.advisory, collector))
        .collect()
}

fn correlate_component_evidence(
    component: &ComponentQuery,
    advisory: &AdvisoryEvidence,
    collector: &mut dyn Collector,
) -> Vec<Verdict> {
    collector.on_trace(&TraceEntry {
        message: format!(
            "correlating component: {}",
            format_component_id(&component.id)
        ),
        detail: None,
    });

    let mut by_vuln: std::collections::BTreeMap<String, Vec<&crate::types::StatusAssertion>> =
        std::collections::BTreeMap::new();
    let mut identity_match_count = 0u32;

    for assertion in &advisory.assertions {
        if matching::matches_component(component, assertion) {
            identity_match_count += 1;
            let version_in_range = matching::check_version(&component.id, assertion);

            collector.on_match(&matching::match_evidence(
                &component.id,
                assertion,
                version_in_range,
            ));

            let qualifier = if version_in_range {
                "EFFECTIVE"
            } else {
                "SKIPPED (version out of range)"
            };

            collector.on_trace(&TraceEntry {
                message: format!(
                    "  {} {} {} from {} [{}]",
                    qualifier,
                    assertion.vulnerability_id,
                    assertion.status.as_str(),
                    assertion.source.identifier,
                    format_matcher(&assertion.matcher),
                ),
                detail: if !version_in_range {
                    Some(matching::explain_skip(&component.id, &assertion.matcher))
                } else {
                    None
                },
            });

            by_vuln
                .entry(assertion.vulnerability_id.clone())
                .or_default()
                .push(assertion);
        }
    }

    if identity_match_count == 0 {
        collector.on_trace(&TraceEntry {
            message: "  no identity matches found in any assertion".into(),
            detail: None,
        });
    }

    // NOTE: this iterates over *every* vulnerability present in the advisory
    // evidence and emits a verdict for each — producing `VerdictStatus::None`
    // for vulnerabilities that had no identity match against this component.
    // That yields a component x vulnerability cross product and conflates
    // "queried, nothing applicable" with "never queried".
    //
    // This is deliberate for the in-memory scenario/WASM path: advisory sets are
    // small and the scenario harness looks up specific CVEs, so an explicit
    // `none` must be present for the expected vulnerability. A production or
    // DB-backed engine MUST NOT do this — it should scope `none` to the
    // vulnerabilities actually queried (or to vulns with at least one identity
    // match), otherwise output grows with the whole corpus. See ADR 00022,
    // "Verdict Semantics": `none` is the result of a query, not a fact asserted
    // about every vulnerability in existence.
    advisory
        .assertions
        .iter()
        .map(|assertion| assertion.vulnerability_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|vuln_id| {
            let matching = by_vuln.get(&vuln_id).cloned().unwrap_or_default();
            let verdict = resolve_verdict(component, &vuln_id, &matching, collector);
            collector.on_verdict(&verdict);
            verdict
        })
        .collect()
}
