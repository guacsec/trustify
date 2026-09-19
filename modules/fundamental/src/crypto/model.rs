use serde::{Deserialize, Serialize};
use trustify_entity::sbom_crypto::CryptoAssetType;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::crypto::service::policy::PolicyVerdict;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct CryptoAlgorithmSummary {
    pub node_id: String,
    pub name: String,
    pub asset_type: CryptoAssetType,
    #[schema(required)]
    pub oid: Option<String>,
    #[schema(value_type = Object)]
    pub properties: serde_json::Value,
    pub policy_status: PolicyVerdict,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct PolicyEvaluationRequest {
    pub sbom_id: Option<Uuid>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct PolicyEvaluationResponse {
    pub summary: PolicySummaryResult,
    pub results: Vec<AlgorithmPolicyResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct PolicySummaryResult {
    pub total: usize,
    pub compliant: usize,
    pub warning: usize,
    pub non_compliant: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AlgorithmPolicyResult {
    pub sbom_id: Uuid,
    pub node_id: String,
    pub name: String,
    #[schema(required)]
    pub oid: Option<String>,
    #[schema(value_type = Object)]
    pub properties: serde_json::Value,
    pub verdict: PolicyVerdict,
}
