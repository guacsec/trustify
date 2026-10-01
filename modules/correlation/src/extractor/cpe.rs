//! CPEs of SBOM nodes. Presentation only, matching is not implemented yet.

use super::{Extractor, NodeIdentifier, NodeRef};
use crate::{
    error::Error,
    model::{IdentifierKind, IdentifierRef},
};
use sea_orm::{ColumnTrait, DatabaseTransaction, EntityTrait, LoaderTrait, QueryFilter};
use tracing::{Instrument, info_span, instrument};
use trustify_entity::{cpe, sbom_node_cpe_ref};
use uuid::Uuid;

/// Provides the CPEs of SBOM nodes.
pub struct CpeExtractor;

#[async_trait::async_trait]
impl Extractor for CpeExtractor {
    fn id(&self) -> &'static str {
        "cpe"
    }

    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn sbom_identifiers(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        let cpe_refs = sbom_node_cpe_ref::Entity::find()
            .filter(sbom_node_cpe_ref::Column::SbomId.eq(sbom_id))
            .all(tx)
            .instrument(info_span!("loading cpe refs"))
            .await?;

        let cpes = cpe_refs
            .load_one(cpe::Entity, tx)
            .instrument(info_span!("loading cpes"))
            .await?;

        Ok(cpe_refs
            .into_iter()
            .zip(cpes)
            .filter_map(|(cpe_ref, cpe)| {
                Some(NodeIdentifier {
                    identifier: IdentifierRef {
                        kind: IdentifierKind::Cpe,
                        value: cpe?.to_string(),
                    },
                    node: NodeRef {
                        sbom_id: cpe_ref.sbom_id,
                        node_id: cpe_ref.node_id,
                    },
                })
            })
            .collect())
    }
}
