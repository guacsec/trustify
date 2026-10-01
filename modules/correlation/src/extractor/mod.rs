//! Extractors produce correlation evidence for one kind of identifier each.
//!
//! Each identifier type (digest, product identifier, ...) lives in its own
//! module, implementing [`Extractor`]. The engine parts ([`Extractors`],
//! [`writer::EvidenceWriter`], the worker and the correlation service) only
//! work against the trait. Adding a new identifier type means adding a module
//! here and registering it in [`Extractors::default`].

pub mod cpe;
pub mod digest;
pub mod product_identifier;
pub mod purl;
pub mod registry;
pub mod worker;
pub mod writer;

pub use registry::Extractors;

use crate::{error::Error, model::IdentifierRef};
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
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status: AssertionStatus,
    pub confidence: f64,
    /// The advisory side value which matched (e.g. a wildcard pattern).
    pub matched_value: String,
}

/// One identifier type the correlation engine can match on.
///
/// Only [`Extractor::id`] and [`Extractor::sbom_identifiers`] are required.
/// The matching functions default to "no match", which allows adding a type
/// for presentation first and implementing matching later.
#[async_trait::async_trait]
pub trait Extractor: Send + Sync {
    /// Stable ID, stored in `correlation_evidence.extractor`.
    ///
    /// Also seeds the namespace of the deterministic evidence IDs, so it must not change.
    fn id(&self) -> &'static str;

    /// Identifiers of this type attached to the nodes of an SBOM.
    ///
    /// Used for SBOM-direction extraction as well as for presenting components.
    async fn sbom_identifiers(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error>;

    /// Interpret a free-text query as identifiers of this type.
    fn parse_query(&self, _query: &str) -> Vec<IdentifierRef> {
        Vec::new()
    }

    /// Find advisory assertions matching the given identifiers.
    ///
    /// Returns pairs of an index into `identifiers` and the matching assertion.
    /// Shared by SBOM-direction extraction and the ad-hoc query.
    async fn match_identifiers(
        &self,
        _identifiers: &[IdentifierRef],
        _tx: &DatabaseTransaction,
    ) -> Result<Vec<(usize, Assertion)>, Error> {
        Ok(Vec::new())
    }

    /// Find SBOM nodes matching the assertions of an advisory.
    async fn match_advisory(
        &self,
        _advisory_id: Uuid,
        _tx: &DatabaseTransaction,
    ) -> Result<Vec<(NodeRef, Assertion)>, Error> {
        Ok(Vec::new())
    }
}
