use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use serde::Deserialize;

use super::evaluator::{AlgorithmInput, EvaluatorFinding, EvaluatorReport, PolicyEvaluator};

pub struct ConformaClient {
    /// Base URL of the running Conforma server (e.g. `http://localhost:8085`).
    /// Start the service with the compose-conforma.yaml overlay before running trustify.
    base_url: String,
}

impl ConformaClient {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    async fn run(&self, input: serde_json::Value) -> Result<RawConformaReport, crate::Error> {
        self.wait_ready().await?;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/v1/validate/input", self.base_url))
            .json(&input)
            .send()
            .await
            .context("failed to reach Conforma evaluation endpoint")?;

        response
            .json()
            .await
            .context("failed to parse Conforma response")
            .map_err(|e| crate::Error::Internal(e.to_string()))
    }

    async fn wait_ready(&self) -> Result<(), crate::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build HTTP client")?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(crate::Error::Internal(
                    "Conforma server did not become ready within 30s".into(),
                ));
            }
            match client.get(format!("{}/ready", self.base_url)).send().await {
                Ok(r) if r.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }
}

#[async_trait]
impl PolicyEvaluator for ConformaClient {
    async fn evaluate(
        &self,
        algorithms: &[AlgorithmInput],
    ) -> Result<EvaluatorReport, crate::Error> {
        let input = serde_json::json!({
            "algorithms": algorithms.iter().map(|a| serde_json::json!({
                "node_id": a.node_id,
                "sbom_id": a.sbom_id,
                "name": a.name,
                "oid": a.oid,
                "properties": a.properties,
            })).collect::<Vec<_>>()
        });

        let raw = self.run(input).await?;
        let file = raw.filepaths.into_iter().next().unwrap_or_default();

        Ok(EvaluatorReport {
            violations: file.violations.into_iter().map(parse_finding).collect(),
            warnings: file.warnings.into_iter().map(parse_finding).collect(),
        })
    }
}

// Conforma strips extra fields from deny/warn results and only preserves "msg".
// We embed the node_id as a "[node_id:<uuid>]" prefix so trustify can parse it
// back out and match violations to individual AlgorithmPolicyResult rows.
fn parse_finding(r: RawResult) -> EvaluatorFinding {
    let node_id = r
        .msg
        .strip_prefix("[node_id:")
        .and_then(|s| s.find(']').map(|i| s[..i].to_string()));
    EvaluatorFinding { node_id }
}

#[derive(Deserialize, Default)]
struct RawConformaReport {
    #[serde(default)]
    filepaths: Vec<RawFilePath>,
}

#[derive(Deserialize, Default)]
struct RawFilePath {
    #[serde(default)]
    violations: Vec<RawResult>,
    #[serde(default)]
    warnings: Vec<RawResult>,
}

#[derive(Deserialize)]
struct RawResult {
    msg: String,
}
