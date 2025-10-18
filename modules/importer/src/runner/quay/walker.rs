use super::oci::Reference;
use crate::{
    model::QuayImporter,
    runner::{
        common::Error,
        context::RunContext,
        progress::{Progress, ProgressInstance},
        quay::oci,
        report::{Message, Phase, ReportBuilder},
    },
};
use anyhow::anyhow;
use futures::{Stream, TryStreamExt, stream};
use reqwest::header;
use serde::Deserialize;
use std::{collections::HashMap, future, sync::Arc};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};

/// Max number of concurrent repository fetches
const DEFAULT_CONCURRENCY: usize = 32;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LastModified(Option<i64>);

pub struct QuayWalker<C: RunContext> {
    continuation: LastModified,
    importer: QuayImporter,
    ingestor: IngestorService,
    report: Arc<Mutex<ReportBuilder>>,
    client: reqwest::Client,
    oci: oci::Client,
    context: C,
}

impl<C: RunContext> QuayWalker<C> {
    pub fn new(
        importer: QuayImporter,
        ingestor: IngestorService,
        report: Arc<Mutex<ReportBuilder>>,
        context: C,
    ) -> Result<Self, Error> {
        let client = match importer.api_token {
            Some(ref token) => authorized_client(token)?,
            None => {
                log::warn!("Quay API token not configured; results may be limited");
                Default::default()
            }
        };
        let oci = oci::Client::new(importer.unencrypted);
        Ok(Self {
            continuation: LastModified(None),
            importer,
            ingestor,
            report,
            client,
            oci,
            context,
        })
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: LastModified) -> Self {
        self.continuation = continuation;
        self
    }

    /// Run the walker
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<LastModified, Error> {
        let progress = self.context.progress(format!(
            "Import SBOM attachments from: {}",
            self.importer.source
        ));
        progress
            .message(format!(
                "Gathering SBOM refs from {}/{}",
                self.importer.source,
                self.importer.namespace.as_deref().unwrap_or_default()
            ))
            .await;

        let references = self.sboms().await?;
        let mut progress = progress.start(references.len());

        for reference in references {
            if let Some(bytes) = self.fetch(&reference).await {
                self.store(&reference, &bytes).await;
            }
            progress.tick().await;
            if self.context.is_canceled().await {
                return Err(Error::Canceled);
            }
        }
        progress.finish().await;

        Ok(LastModified(Some(
            OffsetDateTime::now_utc().unix_timestamp(),
        )))
    }

    async fn fetch(&self, reference: &Reference) -> Option<Vec<u8>> {
        log::debug!("Fetching reference: {reference}");
        match self.oci.fetch(reference).await {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                log::warn!("Error fetching {reference}: {err}");
                let mut report = self.report.lock().await;
                report.add_error(Phase::Retrieval, reference.to_string(), err.to_string());
                None
            }
        }
    }

    async fn store(&self, file: impl std::fmt::Display, data: &[u8]) {
        let result = self
            .ingestor
            .ingest(
                data,
                Format::SBOM,
                Labels::new()
                    .add("source", &self.importer.source)
                    .add("importer", "Quay")
                    .add("file", file.to_string())
                    .extend(self.importer.labels.0.clone()),
                None,
                Cache::Skip,
            )
            .await;
        let mut report = self.report.lock().await;
        match &result {
            Ok(result) => {
                log::debug!("Ingested {file}");
                report.tick();
                report.extend_messages(
                    Phase::Upload,
                    file.to_string(),
                    result.warnings.iter().map(Message::warning),
                );
            }
            Err(err) => {
                log::warn!("Error storing {file}: {err}");
                report.add_error(Phase::Upload, file.to_string(), err.to_string());
            }
        }
    }

    async fn sboms(&self) -> Result<Vec<Reference>, Error> {
        self.repositories(Some(String::new()))
            .try_filter(|repo| future::ready(self.ingestible(repo)))
            .map_ok(|repo| self.repository_details(repo))
            .try_buffer_unordered(self.importer.concurrency.unwrap_or(DEFAULT_CONCURRENCY))
            .map_ok(|repo| {
                stream::iter(
                    repo.sboms(&self.importer.source)
                        .into_iter()
                        .map(Ok::<_, Error>), // try_flatten expects Results
                )
            })
            .try_flatten()
            .try_filter_map(|sbom| future::ready(Ok(self.valid(&sbom).then_some(sbom.reference))))
            .try_collect()
            .await
    }

    fn repositories(&self, page: Option<String>) -> impl Stream<Item = Result<Repository, Error>> {
        stream::try_unfold(page, async |state| match state {
            Some(page) => {
                if self.context.is_canceled().await {
                    return Err(Error::Canceled);
                }
                log::debug!("Fetching batch {page:?}");
                let batch: Batch = self
                    .client
                    .get(self.importer.repositories_url(&page))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                Ok::<_, Error>(Some((
                    stream::iter(batch.repositories.into_iter().map(Ok)),
                    batch.next_page,
                )))
            }
            None => Ok(None),
        })
        .try_flatten()
    }

    async fn repository_details(&self, repo: Repository) -> Result<Repository, Error> {
        if self.context.is_canceled().await {
            return Err(Error::Canceled);
        }
        match (repo.namespace, repo.name) {
            (Some(namespace), Some(name)) => {
                let url = self.importer.repository_url(&namespace, &name);
                log::debug!("Fetching repo {url}");
                Ok(self
                    .client
                    .get(url)
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?)
            }
            _ => Err(Error::Processing(anyhow!(
                "Repository name and namespace are required"
            ))),
        }
    }

    fn ingestible(&self, repo: &Repository) -> bool {
        repo.namespace.is_some()
            && repo.name.is_some()
            && repo.is_public.is_some_and(|x| x)
            && self.modified_since(repo.last_modified)
    }

    fn modified_since(&self, last_modified: Option<i64>) -> bool {
        match last_modified {
            None => false,
            Some(t) => match self.continuation {
                LastModified(Some(v)) => t > v,
                _ => true,
            },
        }
    }

    fn valid(&self, sbom: &Sbom) -> bool {
        match self.importer.size_limit {
            None => true,
            Some(max) => sbom.size <= max.as_u64(),
        }
    }
}

fn authorized_client(token: &str) -> Result<reqwest::Client, Error> {
    let token = format!("Bearer {token}");
    let mut auth_value = header::HeaderValue::from_str(&token)?;
    auth_value.set_sensitive(true);
    let mut headers = header::HeaderMap::new();
    headers.insert(header::AUTHORIZATION, auth_value);
    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .build()?)
}

#[derive(Debug, Deserialize)]
struct Repository {
    namespace: Option<String>,
    name: Option<String>,
    is_public: Option<bool>,
    last_modified: Option<i64>,
    tags: Option<HashMap<String, Tag>>,
}

impl Repository {
    fn sboms(&self, registry: &str) -> Vec<Sbom> {
        match &self.tags {
            Some(tags) => tags
                .values()
                .filter(|t| t.name.ends_with(".sbom"))
                .map(|t| Sbom {
                    reference: Reference::with_tag(
                        registry.to_string(),
                        format!(
                            "{}/{}",
                            self.namespace.clone().unwrap_or_default(),
                            self.name.clone().unwrap_or_default()
                        ),
                        t.name.clone(),
                    ),
                    size: t.size.unwrap_or(u64::MAX),
                })
                .collect(),
            None => vec![],
        }
    }
}

#[derive(Debug, Deserialize)]
struct Batch {
    repositories: Vec<Repository>,
    next_page: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Tag {
    name: String,
    size: Option<u64>,
}

#[derive(Debug)]
struct Sbom {
    reference: Reference,
    size: u64,
}

#[cfg(test)]
mod test {
    use super::*;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, path_regex},
    };

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    #[ignore]
    async fn walk_quay(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let walker = QuayWalker::new(
            QuayImporter {
                source: "quay.io".into(),
                namespace: Some("redhat-user-workloads".into()),
                ..Default::default()
            },
            ctx.ingestor.clone(),
            Arc::new(Mutex::new(ReportBuilder::new())),
            (),
        )?
        .continuation(LastModified(Some(
            OffsetDateTime::now_utc().unix_timestamp(),
        )));
        walker.run().await?;

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn walk_mock_quay(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        // Start a background HTTP server on a random local port
        let quay = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/repository"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(include_str!("../../../../../etc/test-data/quay/repos.json")),
            )
            .mount(&quay)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/repository/redhat-user-workloads/o(11|22)y",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(include_str!("../../../../../etc/test-data/quay/repo.json")),
            )
            .mount(&quay)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r".+sha256-.+\.sbom$"))
            .respond_with(ResponseTemplate::new(200).set_body_string(include_str!(
                "../../../../../etc/test-data/quay/manifest.json"
            )))
            .mount(&quay)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r".+/blobs/sha256:.+$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(include_str!("../../../../../etc/test-data/quay/sbom.json")),
            )
            .mount(&quay)
            .await;

        let walker = QuayWalker::new(
            QuayImporter {
                source: quay.uri()[7..].to_string(),
                unencrypted: true,
                ..Default::default()
            },
            ctx.ingestor.clone(),
            Arc::new(Mutex::new(ReportBuilder::new())),
            (),
        )?;
        walker.run().await?;

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn missing_repo(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        // Start a background HTTP server on a random local port
        let quay = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/repository"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(include_str!("../../../../../etc/test-data/quay/repos.json")),
            )
            .mount(&quay)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/repository/redhat-user-workloads/o11y"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(include_str!("../../../../../etc/test-data/quay/repo.json")),
            )
            .mount(&quay)
            .await;

        let walker = QuayWalker::new(
            QuayImporter {
                source: quay.uri()[7..].to_string(),
                unencrypted: true,
                ..Default::default()
            },
            ctx.ingestor.clone(),
            Arc::new(Mutex::new(ReportBuilder::new())),
            (),
        )?;
        walker.run().await?;

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn invalid_source(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let walker = QuayWalker::new(
            QuayImporter {
                source: "invalid source".into(),
                ..Default::default()
            },
            ctx.ingestor.clone(),
            Arc::new(Mutex::new(ReportBuilder::new())),
            (),
        )?;
        assert!(walker.run().await.is_err());

        Ok(())
    }
}
