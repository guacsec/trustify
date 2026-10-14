use async_trait::async_trait;
use uuid::Uuid;

pub struct AlgorithmInput {
    pub node_id: String,
    pub sbom_id: Uuid,
    pub name: String,
    pub oid: Option<String>,
    pub properties: serde_json::Value,
}

pub struct EvaluatorReport {
    pub violations: Vec<EvaluatorFinding>,
    pub warnings: Vec<EvaluatorFinding>,
}

pub struct EvaluatorFinding {
    pub node_id: Option<String>,
}

#[async_trait]
pub trait PolicyEvaluator: Send + Sync {
    async fn evaluate(
        &self,
        algorithms: &[AlgorithmInput],
    ) -> Result<EvaluatorReport, crate::Error>;
}
