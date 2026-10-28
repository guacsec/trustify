//! Query extensions for SBOM node identifiers.

use crate::{
    sbom_node_checksum, sbom_node_cpe_ref, sbom_node_product_identifier, sbom_node_purl_ref,
};
use sea_orm::{ColumnTrait, QueryFilter, Select};

/// Restrict a query to an optional selection of SBOM nodes.
pub trait ForNodes: Sized {
    /// `None` leaves the query unrestricted; `Some(nodes)` filters by those node IDs.
    /// An empty selection matches no rows. Existing SBOM filters are preserved.
    fn for_nodes(self, nodes: Option<&[&str]>) -> Self;
}

macro_rules! impl_for_nodes {
    ($($entity:ident),+ $(,)?) => {
        $(
            impl ForNodes for Select<$entity::Entity> {
                fn for_nodes(self, nodes: Option<&[&str]>) -> Self {
                    match nodes {
                        Some(nodes) => self.filter($entity::Column::NodeId.is_in(nodes.iter().copied())),
                        None => self,
                    }
                }
            }
        )+
    };
}

impl_for_nodes!(
    sbom_node_checksum,
    sbom_node_cpe_ref,
    sbom_node_product_identifier,
    sbom_node_purl_ref,
);
