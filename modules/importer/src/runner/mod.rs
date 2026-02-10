pub mod clearly_defined_curation;

pub mod clearly_defined;
pub mod common;
pub mod context;
pub mod csaf;
pub mod cve;
pub mod cwe;
pub mod osv;
pub mod progress;
pub mod quay;
pub mod report;
pub mod sbom;

use crate::{
    model::ImporterConfiguration,
    runner::{context::RunContext, report::ScannerError},
    server::RunOutput,
};
use std::path::PathBuf;
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::db::Database;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_storage::service::dispatch::DispatchBackend;

#[derive(Clone)]
pub struct ImportRunner {
    pub db: Database,
    pub storage: DispatchBackend,
    pub working_dir: Option<PathBuf>,
    pub analysis: Option<AnalysisService>,
}

impl ImportRunner {
    #[instrument(skip_all, fields(last_success, continuation), err)]
    pub async fn run_once(
        &self,
        context: impl RunContext + 'static,
        configuration: ImporterConfiguration,
        last_success: Option<OffsetDateTime>,
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let last_success = last_success.map(|t| t.into());

        match configuration {
            ImporterConfiguration::Sbom(sbom) => {
                self.run_once_sbom(context, sbom, last_success).await
            }
            ImporterConfiguration::Csaf(csaf) => {
                self.run_once_csaf(context, csaf, last_success).await
            }
            ImporterConfiguration::Osv(osv) => self.run_once_osv(context, osv, continuation).await,
            ImporterConfiguration::Cve(cve) => self.run_once_cve(context, cve, continuation).await,
            ImporterConfiguration::ClearlyDefined(clearly_defined) => {
                self.run_once_clearly_defined(context, clearly_defined, continuation)
                    .await
            }
            ImporterConfiguration::ClearlyDefinedCuration(clearly_defined) => {
                self.run_once_clearly_defined_curation(context, clearly_defined, continuation)
                    .await
            }
            ImporterConfiguration::Cwe(cwe) => {
                self.run_once_cwe_catalog(context, cwe, continuation).await
            }
            ImporterConfiguration::Quay(quay) => {
                self.run_once_quay(context, quay, continuation).await
            }
        }
    }

    async fn create_working_dir(
        &self,
        r#type: &str,
        source: &str,
    ) -> anyhow::Result<Option<PathBuf>> {
        let Some(working_dir) = &self.working_dir else {
            return Ok(None);
        };

        let result = working_dir.join(r#type).join(&*urlencoding::encode(source));

        tokio::fs::create_dir_all(&result).await?;

        Ok(Some(result))
    }
}
