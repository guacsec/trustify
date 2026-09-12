//! In-memory advisory assertion index.

use crate::{evidence::AdvisoryEvidence, types::StatusAssertion};

/// Indexed advisory assertions retained while building complete Evidence.
#[derive(Debug, Default, Clone)]
pub struct AdvisoryIndex {
    assertions: Vec<StatusAssertion>,
}

impl AdvisoryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, evidence: AdvisoryEvidence) {
        self.assertions.extend(evidence.assertions);
    }

    pub fn assertion_count(&self) -> usize {
        self.assertions.len()
    }

    pub fn evidence(&self) -> AdvisoryEvidence {
        AdvisoryEvidence {
            assertions: self.assertions.clone(),
        }
    }
}
