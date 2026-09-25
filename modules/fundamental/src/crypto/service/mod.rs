pub mod policy;

use crate::{
    Error,
    crypto::{
        model::{
            AlgorithmPolicyResult, CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationResponse,
            PolicySummaryResult,
        },
        service::policy::{PolicyVerdict, evaluate_algorithm},
    },
};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, JoinType, LoaderTrait, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait,
};
use std::collections::{HashMap, HashSet};
use tracing::instrument;
use trustify_common::{
    db::{
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Columns, Filtering, Query},
    },
    model::{PaginatedResults, Pagination},
};
use trustify_entity::{
    package_relates_to_package, relationship::Relationship, sbom_crypto,
    sbom_crypto::CryptoAssetType, sbom_node,
};
use uuid::Uuid;

pub struct CryptoService {
    cache: PaginationCache,
}

impl CryptoService {
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    /// List crypto assets with optional filtering by asset type and SBOM.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn list_algorithms<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: impl Pagination,
        asset_type: Option<CryptoAssetType>,
        sbom_id: Option<Uuid>,
        connection: &C,
    ) -> Result<PaginatedResults<CryptoAlgorithmSummary>, Error> {
        let mut select = sbom_crypto::Entity::find()
            .join(JoinType::InnerJoin, sbom_node::Relation::Crypto.def().rev());

        if let Some(at) = asset_type {
            select = select.filter(sbom_crypto::Column::AssetType.eq(at));
        }

        if let Some(id) = sbom_id {
            select = select.filter(sbom_crypto::Column::SbomId.eq(id));
        }

        let limiter = select
            .filtering_with(
                query,
                Columns::from_entity::<sbom_crypto::Entity>()
                    .add_columns(Columns::from_entity::<sbom_node::Entity>()),
            )?
            .order_by_asc(sbom_crypto::Column::SbomId)
            .order_by_asc(sbom_crypto::Column::NodeId)
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        let nodes = items.load_one(sbom_node::Entity, connection).await?;

        let pkg_counts = self.batch_packages_count(&items, connection).await?;

        let names: Vec<String> = items
            .iter()
            .zip(&nodes)
            .filter_map(|(_, n)| n.as_ref().map(|n| n.name.clone()))
            .collect();
        let sbom_counts = self.batch_sboms_count(&names, connection).await?;

        let algorithms = items
            .into_iter()
            .zip(nodes)
            .filter_map(|(crypto, node)| {
                let node = node?;
                let verdict = evaluate_algorithm(&node.name, &crypto.properties);
                let primitive = crypto
                    .properties
                    .get("algorithmProperties")
                    .and_then(|ap| ap.get("primitive"))
                    .and_then(|p| p.as_str())
                    .map(String::from);
                let pc = pkg_counts
                    .get(&(crypto.sbom_id, crypto.node_id.clone()))
                    .copied()
                    .unwrap_or(0);
                let sc = sbom_counts.get(&node.name).copied().unwrap_or(0);
                Some(CryptoAlgorithmSummary {
                    sbom_id: crypto.sbom_id,
                    node_id: crypto.node_id,
                    name: node.name,
                    asset_type: crypto.asset_type,
                    oid: crypto.oid,
                    primitive,
                    policy_status: verdict,
                    properties: crypto.properties,
                    packages_count: pc,
                    sboms_count: sc,
                })
            })
            .collect();

        Ok(PaginatedResults {
            items: algorithms,
            total,
        })
    }

    /// Compute aggregate KPI metrics across all SBOMs.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn fetch_summary<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<CryptoSummary, Error> {
        let all_algos = sbom_crypto::Entity::find()
            .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm))
            .all(connection)
            .await?;
        let nodes = all_algos.load_one(sbom_node::Entity, connection).await?;

        let total_algorithms = all_algos.len() as i64;
        let mut pqc_compliant: i64 = 0;
        let mut sbom_all_compliant: HashMap<Uuid, bool> = HashMap::new();

        for (crypto, node) in all_algos.iter().zip(&nodes) {
            if let Some(node) = node {
                let verdict = evaluate_algorithm(&node.name, &crypto.properties);
                if verdict == PolicyVerdict::Compliant {
                    pqc_compliant += 1;
                }
                let entry = sbom_all_compliant.entry(crypto.sbom_id).or_insert(true);
                if verdict != PolicyVerdict::Compliant {
                    *entry = false;
                }
            }
        }

        let classical = total_algorithms - pqc_compliant;
        let classical_share_pct = if total_algorithms > 0 {
            (classical as f64 / total_algorithms as f64) * 100.0
        } else {
            0.0
        };

        let sboms_meeting_pqc = sbom_all_compliant.values().filter(|&&v| v).count() as i64;

        Ok(CryptoSummary {
            total_algorithms,
            pqc_compliant,
            classical_share_pct,
            sboms_meeting_pqc,
        })
    }

    /// Count packages related to each crypto asset via Generates relationship.
    async fn batch_packages_count<C: ConnectionTrait>(
        &self,
        items: &[sbom_crypto::Model],
        connection: &C,
    ) -> Result<HashMap<(Uuid, String), i64>, Error> {
        if items.is_empty() {
            return Ok(HashMap::new());
        }

        let mut condition = Condition::any();
        for item in items {
            condition = condition.add(
                Condition::all()
                    .add(package_relates_to_package::Column::SbomId.eq(item.sbom_id))
                    .add(package_relates_to_package::Column::RightNodeId.eq(item.node_id.clone())),
            );
        }

        let rows: Vec<(Uuid, String, i64)> = package_relates_to_package::Entity::find()
            .select_only()
            .column(package_relates_to_package::Column::SbomId)
            .column(package_relates_to_package::Column::RightNodeId)
            .column_as(
                package_relates_to_package::Column::LeftNodeId.count(),
                "packages_count",
            )
            .filter(condition)
            .filter(package_relates_to_package::Column::Relationship.eq(Relationship::Generates))
            .group_by(package_relates_to_package::Column::SbomId)
            .group_by(package_relates_to_package::Column::RightNodeId)
            .into_tuple()
            .all(connection)
            .await?;

        Ok(rows
            .into_iter()
            .map(|(sbom_id, node_id, count)| ((sbom_id, node_id), count))
            .collect())
    }

    /// Count distinct SBOMs containing each algorithm name.
    async fn batch_sboms_count<C: ConnectionTrait>(
        &self,
        names: &[String],
        connection: &C,
    ) -> Result<HashMap<String, i64>, Error> {
        if names.is_empty() {
            return Ok(HashMap::new());
        }

        let unique_names: Vec<&str> = names
            .iter()
            .map(|s| s.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let rows: Vec<(Uuid, String)> = sbom_crypto::Entity::find()
            .join(JoinType::InnerJoin, sbom_node::Relation::Crypto.def().rev())
            .select_only()
            .column(sbom_crypto::Column::SbomId)
            .column(sbom_node::Column::Name)
            .filter(sbom_node::Column::Name.is_in(unique_names))
            .into_tuple()
            .all(connection)
            .await?;

        let mut counts: HashMap<String, HashSet<Uuid>> = HashMap::new();
        for (sbom_id, name) in rows {
            counts.entry(name).or_default().insert(sbom_id);
        }

        Ok(counts
            .into_iter()
            .map(|(name, ids)| (name, ids.len() as i64))
            .collect())
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
