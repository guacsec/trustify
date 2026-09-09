use crate::types::{ComponentQuery, MatchEvidence, SbomInput, TraceEntry, Verdict};

/// Receives correlation events as the engine processes them.
///
/// Callers implement this trait to decide what to keep. A test collector
/// accumulates verdicts for assertion; a UI collector streams results;
/// a DB collector could write to tables.
pub trait Collector {
    /// Called for each assertion that matched (or was checked against) a component.
    fn on_match(&mut self, evidence: &MatchEvidence);

    /// Called when the engine has resolved a final verdict for a component/vulnerability pair.
    fn on_verdict(&mut self, verdict: &Verdict);

    /// Called for each step in the decision trace.
    fn on_trace(&mut self, entry: &TraceEntry);
}

/// The correlation engine. Implementations decide where data comes from
/// and how matching is performed.
pub trait CorrelationEngine {
    /// Correlate a single component identifier against loaded advisories.
    fn correlate_component(&self, component: &ComponentQuery, collector: &mut dyn Collector);

    /// Correlate all components in an SBOM against loaded advisories.
    fn correlate_sbom(&self, sbom: &SbomInput, collector: &mut dyn Collector);
}
