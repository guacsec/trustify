pub mod policy;

use crate::{
    Error,
    crypto::{
        model::{
            AlgorithmPolicyResult, CryptoAlgorithmSummary, PolicyEvaluationResponse,
            PolicySummaryResult,
        },
        service::policy::{PolicyVerdict, evaluate_algorithm},
    },
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, LoaderTrait, QueryFilter, QueryOrder};
use tracing::instrument;
use trustify_common::{
    db::{
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Columns, Filtering, Query},
    },
    model::{PaginatedResults, Pagination},
};
use trustify_entity::{sbom_crypto, sbom_crypto::CryptoAssetType, sbom_node};
use uuid::Uuid;

pub struct CryptoService {
    cache: PaginationCache,
}

impl CryptoService {
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn list_algorithms<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<CryptoAlgorithmSummary>, Error> {
        let limiter = sbom_crypto::Entity::find()
            .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm))
            .filtering_with(query, Columns::from_entity::<sbom_crypto::Entity>())?
            .order_by_asc(sbom_crypto::Column::SbomId)
            .order_by_asc(sbom_crypto::Column::NodeId)
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        let nodes = items.load_one(sbom_node::Entity, connection).await?;

        let algorithms = items
            .into_iter()
            .zip(nodes)
            .filter_map(|(crypto, node)| {
                let node = node?;
                let verdict = evaluate_algorithm(&node.name, &crypto.properties);
                Some(CryptoAlgorithmSummary {
                    node_id: crypto.node_id,
                    name: node.name,
                    asset_type: crypto.asset_type,
                    oid: crypto.oid,
                    policy_status: verdict,
                    properties: crypto.properties,
                })
            })
            .collect();

        Ok(PaginatedResults {
            items: algorithms,
            total,
        })
    }

    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn evaluate_policy<C: ConnectionTrait>(
        &self,
        sbom_id: Option<Uuid>,
        connection: &C,
    ) -> Result<PolicyEvaluationResponse, Error> {
        let mut query = sbom_crypto::Entity::find()
            .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm));

        if let Some(id) = sbom_id {
            query = query.filter(sbom_crypto::Column::SbomId.eq(id));
        }

        let items = query.all(connection).await?;
        let nodes = items.load_one(sbom_node::Entity, connection).await?;

        let results: Vec<AlgorithmPolicyResult> = items
            .into_iter()
            .zip(nodes)
            .filter_map(|(crypto, node)| {
                let node = node?;
                let verdict = evaluate_algorithm(&node.name, &crypto.properties);
                Some(AlgorithmPolicyResult {
                    sbom_id: crypto.sbom_id,
                    node_id: crypto.node_id,
                    name: node.name,
                    oid: crypto.oid,
                    verdict,
                    properties: crypto.properties,
                })
            })
            .collect();

        let summary = PolicySummaryResult {
            total: results.len(),
            compliant: results
                .iter()
                .filter(|r| r.verdict == PolicyVerdict::Compliant)
                .count(),
            warning: results
                .iter()
                .filter(|r| r.verdict == PolicyVerdict::Warning)
                .count(),
            non_compliant: results
                .iter()
                .filter(|r| r.verdict == PolicyVerdict::NonCompliant)
                .count(),
        };

        Ok(PolicyEvaluationResponse { summary, results })
    }
}
