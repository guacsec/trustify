use sea_orm::entity::prelude::*;

/// An assertion context (product) a piece of correlation evidence was matched in.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_evidence_context")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub evidence_id: Uuid,
    #[sea_orm(primary_key)]
    pub context_id: Uuid,
    /// Where the SBOM node got the matching identifier from.
    pub source: ContextSource,
    /// Hops from the node (ancestor node) or SBOM (ancestor SBOM), 0 otherwise.
    pub distance: i32,
    /// The SBOM side identifier which matched: a CPE (2.3 formatted string), or an exact product
    /// identifier as `<kind>:<value>` (e.g. `sku:6925281924439`).
    #[sea_orm(primary_key)]
    pub node_identifier: String,
    /// The context's identifier which matched, in the same format.
    #[sea_orm(primary_key)]
    pub context_identifier: String,
    /// The confidence of this context: its source and distance, and the kind of match.
    pub confidence: f64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::correlation_evidence::Entity",
        from = "Column::EvidenceId",
        to = "super::correlation_evidence::Column::Id",
        on_delete = "Cascade"
    )]
    Evidence,
    #[sea_orm(
        belongs_to = "super::assertion_context::Entity",
        from = "Column::ContextId",
        to = "super::assertion_context::Column::Id"
    )]
    Context,
}

impl Related<super::correlation_evidence::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Evidence.def()
    }
}

impl Related<super::assertion_context::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Context.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// Where an SBOM node got a CPE putting it into a product from.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, EnumIter, DeriveActiveEnum)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "correlation_context_source"
)]
pub enum ContextSource {
    /// The node's own CPE.
    #[sea_orm(string_value = "node")]
    Node,
    /// The CPE of an ancestor node in the same SBOM.
    #[sea_orm(string_value = "ancestor_node")]
    AncestorNode,
    /// A describing CPE of the SBOM.
    #[sea_orm(string_value = "describing")]
    Describing,
    /// A describing CPE of an ancestor SBOM.
    #[sea_orm(string_value = "ancestor_sbom")]
    AncestorSbom,
    /// The product of an RPM, by the `distro=` qualifier of its PURL.
    #[sea_orm(string_value = "purl_qualifier")]
    PurlQualifier,
    /// The product of an RPM, by the release (stream, codestream) of its version.
    #[sea_orm(string_value = "purl_release")]
    PurlRelease,
    /// Nothing in the SBOM confirms the context, nor contradicts it. The context identifier lists
    /// the identifiers which would have confirmed it.
    #[sea_orm(string_value = "unconfirmed")]
    Unconfirmed,
}
