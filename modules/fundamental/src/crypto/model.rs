use serde::{Deserialize, Serialize};
use trustify_entity::sbom_crypto::CryptoAssetType;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::crypto::service::policy::PolicyVerdict;

/// Summary of a cryptographic asset found in SBOMs.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct CryptoAlgorithmSummary {
    pub sbom_id: Uuid,
    pub node_id: String,
    pub name: String,
    pub asset_type: CryptoAssetType,
    #[schema(required)]
    pub oid: Option<String>,
    #[schema(required)]
    pub primitive: Option<String>,
    #[schema(value_type = Object)]
    pub properties: serde_json::Value,
    pub policy_status: PolicyVerdict,
    pub packages_count: i64,
    pub sboms_count: i64,
    /// NIST PQC replacement recommendation for this algorithm, if a mapping exists.
    #[schema(required)]
    pub recommendation: Option<String>,
}

/// Aggregate KPI metrics for cryptographic assets across all SBOMs.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct CryptoSummary {
    pub total_algorithms: i64,
    pub pqc_compliant: i64,
    pub classical_share_pct: f64,
    pub sboms_meeting_pqc: i64,
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

/// A single algorithm-to-NIST-replacement remediation mapping.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct RemediationMapping {
    pub id: Uuid,
    pub algorithm_name: String,
    #[schema(required)]
    pub algorithm_primitive: Option<String>,
    pub replacement_name: String,
    #[schema(required)]
    pub replacement_standard: Option<String>,
    #[schema(required)]
    pub replacement_primitive: Option<String>,
}
