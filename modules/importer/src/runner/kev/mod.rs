mod walker;

use crate::{
    model::KevImporter,
    runner::{
        RunOutput,
        context::RunContext,
        kev::walker::KevWalker,
        report::{ReportBuilder, ScannerError},
    },
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_module_ingestor::{graph::Graph, service::IngestorService};

impl super::ImportRunner {
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn run_once_kev_catalog(
        &self,
        context: impl RunContext + 'static,
        kev_catalog: KevImporter,
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor =
            IngestorService::new(Graph::new(), self.storage.clone(), self.analysis.clone());

        let report = Arc::new(Mutex::new(ReportBuilder::new()));
        let continuation = serde_json::from_value(continuation).unwrap_or_default();

        let walker = KevWalker::new(
            kev_catalog.source.clone(),
            kev_catalog.catalog.clone(),
            ingestor,
            self.db.clone(),
            report.clone(),
        )
        .continuation(continuation);

        match walker.run().await {
            Ok(continuation) => {
                // extract the report
                let report = match Arc::try_unwrap(report) {
                    Ok(report) => report.into_inner(),
                    Err(report) => report.lock().await.clone(),
                }
                .build();
                Ok(RunOutput {
                    report,
                    continuation: serde_json::to_value(continuation).ok(),
                })
            }
            Err(err) => Err(ScannerError::Normal {
                err: err.into(),
                output: RunOutput {
                    report: report.lock().await.clone().build(),
                    continuation: None,
                },
            }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::runner::{
        ImportRunner,
        kev::walker::KevWalker,
        report::{Phase, ReportBuilder, Severity},
    };
    use sea_orm::EntityTrait;
    use std::{collections::HashSet, time::Duration};
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::ReadWrite;
    use trustify_entity::exploit;
    use trustify_test_context::TrustifyContext;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const LAST_MODIFIED: &str = "Wed, 21 Oct 2015 07:28:00 GMT";
    const CATALOG: &str =
        include_str!("../../../../../etc/test-data/kev/known_exploited_vulnerabilities.json");
    const CATALOG_ENTRY_REMOVED: &str = include_str!(
        "../../../../../etc/test-data/kev/known_exploited_vulnerabilities-entry-removed.json"
    );

    fn importer(source: &str, catalog: Option<&str>) -> KevImporter {
        KevImporter {
            common: Default::default(),
            source: source.to_string(),
            catalog: catalog.map(ToString::to_string),
        }
    }

    fn runner(ctx: &TrustifyContext) -> ImportRunner {
        ImportRunner {
            db: ReadWrite::new(ctx.db.clone()),
            storage: ctx.storage.clone().into(),
            working_dir: None,
            analysis: None,
        }
    }

    /// Serve `body` at the catalog path, with a `Last-Modified` header.
    async fn catalog_server(body: &str, status: u16) -> MockServer {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/known_exploited_vulnerabilities.json"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Last-Modified", LAST_MODIFIED)
                    .set_body_string(body),
            )
            .mount(&server)
            .await;

        server
    }

    fn source(server: &MockServer) -> String {
        format!("{}/known_exploited_vulnerabilities.json", server.uri())
    }

    async fn entries(ctx: &TrustifyContext) -> Result<Vec<String>, anyhow::Error> {
        Ok(exploit::Entity::find()
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|entry| entry.cve_id)
            .collect())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_mock_kev(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let server = catalog_server(CATALOG, 200).await;

        let output = runner(ctx)
            .run_once_kev_catalog(
                (),
                importer(&source(&server), None),
                serde_json::Value::Null,
            )
            .await?;

        assert!(
            output.report.messages.is_empty(),
            "{:?}",
            output.report.messages
        );
        // the catalog counts as one processed item
        assert_eq!(output.report.number_of_items, 1);
        assert_eq!(entries(ctx).await?.len(), 3);

        // the Last-Modified header is retained as the continuation
        let continuation = output.continuation.expect("continuation state");
        assert_eq!(
            serde_json::from_value::<Option<String>>(continuation.clone())?.as_deref(),
            Some(LAST_MODIFIED)
        );

        // A second run against an unchanged Last-Modified skips processing:
        // this server would serve a catalog with one entry removed, but the
        // database is left untouched.
        let unchanged = catalog_server(CATALOG_ENTRY_REMOVED, 200).await;
        let output = runner(ctx)
            .run_once_kev_catalog(
                (),
                importer(&source(&unchanged), None),
                continuation.clone(),
            )
            .await?;

        assert_eq!(entries(ctx).await?.len(), 3);
        assert_eq!(output.continuation, Some(continuation));
        // nothing was processed, so nothing is counted
        assert_eq!(output.report.number_of_items, 0);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_kev_http_error_fails(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let server = catalog_server("gateway is down", 502).await;

        let result = runner(ctx)
            .run_once_kev_catalog(
                (),
                importer(&source(&server), None),
                serde_json::Value::Null,
            )
            .await;

        // an http error status must fail the run
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("502"),
            "error must name the status: {err}"
        );
        assert!(entries(ctx).await?.is_empty());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_kev_stores_configured_catalog(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let server = catalog_server(CATALOG, 200).await;

        runner(ctx)
            .run_once_kev_catalog(
                (),
                importer(&source(&server), Some("mirror")),
                serde_json::Value::Null,
            )
            .await?;

        let sources = exploit::Entity::find()
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|entry| entry.source)
            .collect::<HashSet<_>>();
        assert_eq!(sources, ["mirror".to_string()].into_iter().collect());

        Ok(())
    }

    /// A host that accepts the connection then goes silent must fail the run,
    /// not block it forever.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_kev_times_out_on_a_stalled_server(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/known_exploited_vulnerabilities.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(CATALOG)
                    .set_delay(Duration::from_secs(30)),
            )
            .mount(&server)
            .await;

        let runner = runner(ctx);
        let ingestor = IngestorService::new(Graph::new(), runner.storage.clone(), None);
        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let err = KevWalker::new(
            source(&server),
            None,
            ingestor,
            ReadWrite::new(ctx.db.clone()),
            report,
        )
        .timeouts(Duration::from_millis(200), Duration::from_millis(200))
        .run()
        .await
        .expect_err("a stalled server must fail the run");

        // reqwest reports the cause down the source chain, not in the top message
        let chain = std::iter::successors(Some(&err as &dyn std::error::Error), |err| err.source())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(": ");
        assert!(
            chain.contains("timed out") || chain.contains("timeout"),
            "error should name the timeout: {chain}"
        );
        assert!(entries(ctx).await?.is_empty());

        Ok(())
    }

    /// The loader's warnings have to reach the report, or a catalog whose dates
    /// are unusable leaves no trace in the import history.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_kev_reports_loader_warnings(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let catalog = serde_json::json!({
            "catalogVersion": "2025.07.28",
            "vulnerabilities": [{"cveID": "CVE-2099-0001", "dateAdded": "17/07/2025"}],
        })
        .to_string();
        let server = catalog_server(&catalog, 200).await;

        let output = runner(ctx)
            .run_once_kev_catalog(
                (),
                importer(&source(&server), None),
                serde_json::Value::Null,
            )
            .await?;

        // the entry is still ingested, only its date was dropped
        assert_eq!(entries(ctx).await?, ["CVE-2099-0001"]);
        assert_eq!(output.report.number_of_items, 1);

        let messages = output.report.messages[&Phase::Upload][&source(&server)].clone();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].severity, Severity::Warning);
        assert!(
            messages[0].message.contains("dateAdded"),
            "unexpected message: {}",
            messages[0].message
        );

        Ok(())
    }
}
