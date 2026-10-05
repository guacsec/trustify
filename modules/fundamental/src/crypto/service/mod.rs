pub mod conforma;
pub mod evaluator;
pub mod policy;

use crate::{
    Error,
    crypto::{
        model::{
            AlgorithmPolicyResult, CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationResponse,
            PolicySummaryResult,
        },
        service::policy::PolicyVerdict,
    },
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, Condition, ConnectionTrait, EntityTrait, JoinType,
    LoaderTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait,
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
    evaluator: Option<Box<dyn evaluator::PolicyEvaluator>>,
}

impl CryptoService {
    pub fn new(cache: PaginationCache, conforma_url: Option<String>) -> Self {
        Self {
            cache,
            evaluator: conforma_url
                .map(conforma::ConformaClient::new)
                .map(|c| Box::new(c) as Box<dyn evaluator::PolicyEvaluator>),
        }
    }

    pub fn has_evaluator(&self) -> bool {
        self.evaluator.is_some()
    }

    #[cfg(test)]
    pub fn with_evaluator(
        cache: PaginationCache,
        evaluator: Box<dyn evaluator::PolicyEvaluator>,
    ) -> Self {
        Self {
            cache,
            evaluator: Some(evaluator),
        }
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
                let policy_status = crypto.policy_verdict.as_deref().and_then(|v| match v {
                    "compliant" => Some(PolicyVerdict::Compliant),
                    "warning" => Some(PolicyVerdict::Warning),
                    "non_compliant" => Some(PolicyVerdict::NonCompliant),
                    _ => None,
                });
                Some(CryptoAlgorithmSummary {
                    sbom_id: crypto.sbom_id,
                    node_id: crypto.node_id,
                    name: node.name,
                    asset_type: crypto.asset_type,
                    oid: crypto.oid,
                    primitive,
                    properties: crypto.properties,
                    packages_count: pc,
                    sboms_count: sc,
                    policy_status,
                })
            })
            .collect();

        Ok(PaginatedResults {
            items: algorithms,
            total,
        })
    }

    /// Aggregate stored policy verdicts from the DB without calling Conforma.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn fetch_policy_summary<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<PolicySummaryResult, Error> {
        let rows: Vec<Option<String>> = sbom_crypto::Entity::find()
            .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm))
            .select_only()
            .column(sbom_crypto::Column::PolicyVerdict)
            .into_tuple()
            .all(connection)
            .await?;

        let total = rows.len();
        let mut compliant = 0usize;
        let mut warning = 0usize;
        let mut non_compliant = 0usize;

        for verdict in &rows {
            match verdict.as_deref() {
                Some("compliant") => compliant += 1,
                Some("warning") => warning += 1,
                Some("non_compliant") => non_compliant += 1,
                _ => {}
            }
        }

        Ok(PolicySummaryResult {
            total,
            compliant,
            warning,
            non_compliant,
        })
    }

    /// Compute aggregate KPI metrics across all SBOMs.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn fetch_summary<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<CryptoSummary, Error> {
        let total_algorithms = sbom_crypto::Entity::find()
            .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm))
            .count(connection)
            .await? as i64;

        Ok(CryptoSummary { total_algorithms })
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
        let policy_evaluator = self
            .evaluator
            .as_ref()
            .ok_or_else(|| Error::Internal("CONFORMA_URL is not configured".into()))?;

        let mut query = sbom_crypto::Entity::find()
            .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm));

        if let Some(id) = sbom_id {
            query = query.filter(sbom_crypto::Column::SbomId.eq(id));
        }

        let items = query.all(connection).await?;
        let nodes = items.load_one(sbom_node::Entity, connection).await?;

        let algo_input: Vec<evaluator::AlgorithmInput> = items
            .iter()
            .zip(nodes.iter())
            .filter_map(|(crypto, node)| {
                let node = node.as_ref()?;
                Some(evaluator::AlgorithmInput {
                    node_id: crypto.node_id.clone(),
                    sbom_id: crypto.sbom_id,
                    name: node.name.clone(),
                    oid: crypto.oid.clone(),
                    properties: crypto.properties.clone(),
                })
            })
            .collect();

        let report = policy_evaluator.evaluate(&algo_input).await?;

        let violation_ids: HashSet<&str> = report
            .violations
            .iter()
            .filter_map(|v| v.node_id.as_deref())
            .collect();

        let warning_ids: HashSet<&str> = report
            .warnings
            .iter()
            .filter_map(|w| w.node_id.as_deref())
            .collect();

        let results: Vec<AlgorithmPolicyResult> = items
            .into_iter()
            .zip(nodes)
            .filter_map(|(crypto, node)| {
                let node = node?;
                let verdict = if violation_ids.contains(crypto.node_id.as_str()) {
                    PolicyVerdict::NonCompliant
                } else if warning_ids.contains(crypto.node_id.as_str()) {
                    PolicyVerdict::Warning
                } else {
                    PolicyVerdict::Compliant
                };
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

        // Persist verdicts so list_algorithms can return policy_status without
        // calling Conforma on every read request.
        for result in &results {
            let verdict_str = match result.verdict {
                PolicyVerdict::Compliant => "compliant",
                PolicyVerdict::Warning => "warning",
                PolicyVerdict::NonCompliant => "non_compliant",
            };
            let active: sbom_crypto::ActiveModel = sbom_crypto::ActiveModel {
                sbom_id: ActiveValue::Unchanged(result.sbom_id),
                node_id: ActiveValue::Unchanged(result.node_id.clone()),
                policy_verdict: ActiveValue::Set(Some(verdict_str.to_string())),
                ..Default::default()
            };
            active
                .update(connection)
                .await
                .map_err(|e| Error::Internal(format!("failed to persist policy verdict: {e}")))?;
        }

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
