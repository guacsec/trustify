//! Query extensions for SBOM node identifiers.

use crate::{
    sbom_node_checksum, sbom_node_cpe_ref, sbom_node_product_identifier, sbom_node_purl_ref,
};
use sea_orm::{
    QueryFilter, Select,
    sea_query::{Expr, ExprTrait, PgFunc},
};

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
                        // a single array parameter, as the number of nodes is unbounded
                        Some(nodes) => self.filter(
                            Expr::col(($entity::Entity, $entity::Column::NodeId)).eq(PgFunc::any(
                                nodes.iter().map(|node| node.to_string()).collect::<Vec<_>>(),
                            )),
                        ),
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
