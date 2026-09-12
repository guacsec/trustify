//! Collector implementations for evidence, verdict, and trace events.

use crate::{
    engine::Collector,
    types::{MatchEvidence, TraceEntry, Verdict},
};

/// A simple collector that accumulates all verdicts into a Vec.
#[derive(Debug, Default)]
pub struct VecCollector {
    pub verdicts: Vec<Verdict>,
    pub evidence: Vec<MatchEvidence>,
    pub trace: Vec<TraceEntry>,
}

impl Collector for VecCollector {
    fn on_match(&mut self, evidence: &MatchEvidence) {
        self.evidence.push(evidence.clone());
    }

    fn on_verdict(&mut self, verdict: &Verdict) {
        self.verdicts.push(verdict.clone());
    }

    fn on_trace(&mut self, entry: &TraceEntry) {
        self.trace.push(entry.clone());
    }
}

/// A collector that only keeps verdicts (ignores evidence and trace).
#[derive(Debug, Default)]
pub struct VerdictCollector {
    pub verdicts: Vec<Verdict>,
}

impl Collector for VerdictCollector {
    fn on_match(&mut self, _evidence: &MatchEvidence) {}

    fn on_verdict(&mut self, verdict: &Verdict) {
        self.verdicts.push(verdict.clone());
    }

    fn on_trace(&mut self, _entry: &TraceEntry) {}
}

/// A collector that only records the trace (for debugging/explain mode).
#[derive(Debug, Default)]
pub struct TraceCollector {
    pub trace: Vec<TraceEntry>,
}

impl Collector for TraceCollector {
    fn on_match(&mut self, _evidence: &MatchEvidence) {}
    fn on_verdict(&mut self, _verdict: &Verdict) {}

    fn on_trace(&mut self, entry: &TraceEntry) {
        self.trace.push(entry.clone());
    }
}
