//! Rules deriving implied version ranges from what advisories state.
//!
//! Ingestion only stores what a document states. Some publishers imply more than they state, e.g.
//! Red Hat only lists the version fixing a vulnerability, implying that earlier versions (of the
//! same stream) are affected. A rule turns such statements into additional candidate ranges,
//! which the PURL extractor matches like stated ones (including the stream scoping), and reports
//! as evidence of the rule's own type.
//!
//! To add a rule, implement [`RangeRule`] in a new module and add it to [`rules`].

mod redhat;

use super::Candidates;

/// Derives additional, implied version ranges from the statements of an advisory.
pub trait RangeRule: Send + Sync {
    /// Evidence type of matches on derived ranges, e.g. `purl_rh_fixed`.
    fn id(&self) -> &'static str;

    /// Confidence factor, applied on top of the confidence of the stream scoping.
    fn confidence(&self) -> f64;

    /// The derived candidates, as SQL over the stated rows.
    fn candidates(&self) -> Candidates;
}

/// All active rules.
pub fn rules() -> Vec<Box<dyn RangeRule>> {
    vec![Box::new(redhat::RedHatFixed)]
}
