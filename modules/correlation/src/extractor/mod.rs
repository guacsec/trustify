//! Extractors produce correlation evidence for one kind of identifier each.
//!
//! Each identifier type (digest, product identifier, ...) lives in its own
//! module, implementing [`Extractor`]. The engine parts ([`Extractors`],
//! [`writer::EvidenceWriter`], the worker and the correlation service) only
//! work against the trait. Adding a new identifier type means adding a module
//! here and registering it in [`Extractors::default`].

pub mod context;
pub mod cpe;
pub mod digest;
pub mod product_identifier;
pub mod purl;
pub mod registry;
pub mod version;
pub mod worker;
pub mod writer;

pub use registry::Extractors;

use crate::{
    error::Error,
    model::{ConfidenceFactor, IdentifierRef, MatchedValue, combine},
};
use sea_orm::DatabaseTransaction;
use trustify_entity::correlation_evidence::AssertionStatus;
use uuid::Uuid;

/// A node (component) inside an SBOM.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeRef {
    pub sbom_id: Uuid,
    pub node_id: String,
}

/// An identifier attached to an SBOM node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentifier {
    pub node: NodeRef,
    pub identifier: IdentifierRef,
}

/// A vulnerability assertion of an advisory which matched an identifier.
#[derive(Clone, Debug, PartialEq)]
pub struct Assertion {
    /// The type of evidence, stored in `correlation_evidence.extractor`.
    ///
    /// Usually the ID of the extractor. An extractor with several matching strategies reports
    /// each under its own type (e.g. `purl` and `purl_stream`). It also seeds the namespace of the
    /// deterministic evidence IDs, so it must not change.
    pub extractor: &'static str,
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status: AssertionStatus,
    /// The product of the [`Self::factors`].
    pub confidence: f64,
    /// The factors of the confidence, and why they apply.
    pub factors: Vec<ConfidenceFactor>,
    /// The advisory side value which matched (e.g. a wildcard pattern and version ranges).
    pub matched_value: MatchedValue,
    /// The product (assertion context) the assertion is stated in, if any.
    pub context_id: Option<Uuid>,
    /// Whether the assertion only applies to a node in its context, e.g. a versionless
    /// statement, which identifies the package only through its product.
    pub requires_context: bool,
    /// The versions the node's own version must be in, when the matched identifier doesn't pin a
    /// version (e.g. the model number of a firmware). See [`version::retain_in_range`].
    pub version_range_id: Option<Uuid>,
}

impl Assertion {
    /// Apply another factor to the confidence.
    pub fn apply(&mut self, factor: ConfidenceFactor) {
        self.factors.push(factor);
        self.confidence = combine(&self.factors);
    }
}

/// An assertion matching one of the identifiers passed to [`Extractor::match_identifiers`].
#[derive(Clone, Debug, PartialEq)]
pub struct IdentifierMatch {
    /// Index into the identifiers passed in.
    pub index: usize,
    pub assertion: Assertion,
}

/// An SBOM node matching an assertion, found by [`Extractor::match_advisory`].
#[derive(Clone, Debug, PartialEq)]
pub struct NodeMatch {
    pub node: NodeRef,
    pub assertion: Assertion,
}

/// One identifier type the correlation engine can match on.
///
/// Only [`Extractor::id`] and [`Extractor::sbom_identifiers`] are required.
/// The matching functions default to "no match", which allows adding a type
/// for presentation first and implementing matching later.
#[async_trait::async_trait]
pub trait Extractor: Send + Sync {
    /// Stable ID of the extractor, used for logging.
    ///
    /// The evidence itself is stored under the type of each [`Assertion::extractor`], which
    /// usually is this ID.
    fn id(&self) -> &'static str;

    /// Identifiers of this type attached to the nodes of an SBOM.
    ///
    /// Used for SBOM-direction extraction as well as for presenting components.
    async fn sbom_identifiers(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error>;

    /// Find advisory assertions matching the given identifiers.
    ///
    /// Identifiers of kinds this extractor does not handle must be ignored.
    /// Shared by SBOM-direction extraction and the ad-hoc query.
    async fn match_identifiers(
        &self,
        _identifiers: &[IdentifierRef],
        _tx: &DatabaseTransaction,
    ) -> Result<Vec<IdentifierMatch>, Error> {
        Ok(Vec::new())
    }

    /// Find SBOM nodes matching the assertions of an advisory.
    async fn match_advisory(
        &self,
        _advisory_id: Uuid,
        _tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
        Ok(Vec::new())
    }
}
