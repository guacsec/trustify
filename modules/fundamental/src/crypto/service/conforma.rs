use std::{net::TcpListener, path::Path, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use serde::Deserialize;
use tokio::process::Command;

use super::evaluator::{AlgorithmInput, EvaluatorFinding, EvaluatorReport, PolicyEvaluator};

pub struct ConformaClient {
    /// Absolute path to a local Conforma policy YAML file.
    /// In the future this path will point to a dynamically generated file
    /// built from the user's chosen policy configuration.
    policy_path: String,
    image: String,
}

impl ConformaClient {
    pub fn new(policy_path: String) -> Self {
        Self {
            policy_path,
            image: "quay.io/conforma/cli:latest".to_string(),
        }
    }

    async fn run(&self, input: serde_json::Value) -> Result<RawConformaReport, crate::Error> {
        let (container_id, port) = self.start_server().await?;
        let result = self.call_server(&container_id, port, input).await;
        self.stop_server(&container_id).await;
        result
    }

    async fn start_server(&self) -> Result<(String, u16), crate::Error> {
        // Bind to port 0 to let the OS pick a free port, then release it before
        // passing the number to podman. There's a small TOCTOU window but it's
        // the most portable approach across podman versions (port 0 in -p is not
        // universally supported).
        let port = {
            let listener =
                TcpListener::bind("127.0.0.1:0").context("failed to find a free local port")?;
            listener
                .local_addr()
                .context("failed to get local addr")?
                .port()
        };
        let port_str = port.to_string();

        let policy_path = Path::new(&self.policy_path);
        let policy_dir = policy_path.parent().ok_or_else(|| {
            crate::Error::Internal("CONFORMA_POLICY must be an absolute file path".into())
        })?;
        let policy_filename = policy_path
            .file_name()
            .ok_or_else(|| crate::Error::Internal("CONFORMA_POLICY path has no filename".into()))?
            .to_string_lossy();
        let container_policy = format!("/policy/{policy_filename}");

        // --network=host: Conforma binds to 127.0.0.1 inside the container; with
        // rootless podman + slirp4netns, port-mapping can't forward to the container
        // loopback, so we share the host network namespace instead.
        // `:z` sets the SELinux label so rootless podman on Fedora/RHEL can read the file.
        // Mount the whole policy directory so policy.yaml can reference sibling .rego files.
        let volume_mount = format!("{}:/policy:ro,z", policy_dir.display());
        let output = Command::new("podman")
            .args([
                "run",
                "-d",
                "--rm",
                "--network=host",
                "-v",
                &volume_mount,
                &self.image,
                "validate",
                "input",
                "--server",
                "--server-port",
                &port_str,
                "--policy",
                &container_policy,
            ])
            .output()
            .await
            .context("failed to launch Conforma container via podman")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::Error::Internal(format!(
                "podman run failed: {stderr}"
            )));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if container_id.is_empty() {
            return Err(crate::Error::Internal(
                "podman returned empty container ID".into(),
            ));
        }
        Ok((container_id, port))
    }

    async fn call_server(
        &self,
        _container_id: &str,
        port: u16,
        input: serde_json::Value,
    ) -> Result<RawConformaReport, crate::Error> {
        let base_url = format!("http://127.0.0.1:{port}");
        self.wait_ready(&base_url).await?;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/v1/validate/input"))
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

    async fn wait_ready(&self, base_url: &str) -> Result<(), crate::Error> {
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
            match client.get(format!("{base_url}/ready")).send().await {
                Ok(r) if r.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }

    async fn stop_server(&self, container_id: &str) {
        let _ = Command::new("podman")
            .args(["stop", container_id])
            .output()
            .await;
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
