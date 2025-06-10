use super::oci::Reference;
use crate::model::QuayImporter;
use crate::runner::common::Error;
use crate::runner::context::RunContext;
use crate::runner::progress::{Progress, ProgressInstance};
use crate::runner::quay::oci;
use crate::runner::report::{Message, Phase, ReportBuilder};
use futures::{Stream, StreamExt, future, stream};
use reqwest::header;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};

const QUAY_API_TOKEN: &str = "QUAY_API_TOKEN";

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LastModified(Option<i64>);

pub struct QuayWalker<C: RunContext> {
    continuation: LastModified,
    importer: QuayImporter,
    ingestor: IngestorService,
    report: Arc<Mutex<ReportBuilder>>,
    client: reqwest::Client,
    context: C,
}

impl<C: RunContext> QuayWalker<C> {
    pub fn new(
        importer: QuayImporter,
        ingestor: IngestorService,
        report: Arc<Mutex<ReportBuilder>>,
        context: C,
    ) -> Result<Self, Error> {
        let client = match std::env::var(QUAY_API_TOKEN) {
            Ok(token) => authorized_client(token)?,
            _ => {
                log::warn!("{QUAY_API_TOKEN} not set in environment; results will be limited");
                Default::default()
            }
        };
        Ok(Self {
            continuation: LastModified(None),
            importer,
            ingestor,
            report,
            client,
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
        let oci = oci::Client::new();

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

        let references = self.sboms().await;
        let mut progress = progress.start(references.len());

        for reference in references {
            let bytes = oci.fetch(&reference).await?;
            self.store(&reference, &bytes).await?;
            progress.tick().await;
            log::debug!("Ingested {reference}");
            if self.context.is_canceled().await {
                break;
            }
        }
        progress.finish().await;

        Ok(LastModified(Some(
            OffsetDateTime::now_utc().unix_timestamp(),
        )))
    }

    async fn store(&self, file: impl ToString, data: &[u8]) -> Result<(), Error> {
        let mut report = self.report.lock().await;
        report.tick();
        match self
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
            .await
        {
            Ok(result) => report.extend_messages(
                Phase::Upload,
                file.to_string(),
                result.warnings.into_iter().map(Message::warning),
            ),
            Err(err) => report.add_error(Phase::Upload, file.to_string(), err.to_string()),
        };
        Ok(())
    }

    async fn sboms(&self) -> Vec<Reference> {
        let tags: Vec<(Reference, u64)> = self
            .repositories(Some(String::new()))
            .await
            .filter(|repo| future::ready(repo.is_public && self.modified_since(repo.last_modified)))
            .map(|repo| self.repository(repo.namespace, repo.name))
            .buffer_unordered(32) // TODO: make configurable
            .filter_map(|repo| future::ready(repo.unwrap_or_default().sboms(&self.importer.source)))
            .map(stream::iter)
            .flatten()
            .collect()
            .await;
        tags.into_iter()
            .filter_map(|(reference, size)| {
                if self.too_big(size) {
                    None
                } else {
                    Some(reference)
                }
            })
            .collect()
    }

    async fn repositories(&self, page: Option<String>) -> impl Stream<Item = Repository> {
        stream::unfold(page, async |state| match state {
            None => None,
            Some(page) => {
                let batch: Batch = match self
                    .client
                    .get(self.importer.repositories_url(&page))
                    .send()
                    .await
                {
                    Ok(response) => response.json().await.unwrap_or_default(),
                    Err(e) => {
                        log::warn!("Encountered error fetching Quay repositories: {e}");
                        Batch::default()
                    }
                };
                Some((stream::iter(batch.repositories), batch.next_page))
            }
        })
        .flatten()
        .boxed_local()
    }

    async fn repository(&self, namespace: String, name: String) -> Result<Repository, Error> {
        log::debug!("Fetching {}/{namespace}/{name}", self.importer.source);
        Ok(self
            .client
            .get(self.importer.repository_url(&namespace, &name))
            .send()
            .await?
            .json()
            .await?)
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

    fn too_big(&self, size: u64) -> bool {
        match self.importer.size_limit {
            None => false,
            Some(max) => size > max.as_u64(),
        }
    }
}

fn authorized_client(token: String) -> Result<reqwest::Client, Error> {
    let token = format!("Bearer {token}");
    let mut auth_value = header::HeaderValue::from_str(&token)?;
    auth_value.set_sensitive(true);
    let mut headers = header::HeaderMap::new();
    headers.insert(header::AUTHORIZATION, auth_value);
    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .build()?)
}

#[derive(Debug, Default, Deserialize)]
struct Repository {
    namespace: String,
    name: String,
    is_public: bool,
    last_modified: Option<i64>,
    tags: Option<HashMap<String, Tag>>,
}

impl Repository {
    fn sboms(&self, registry: &str) -> Option<Vec<(Reference, u64)>> {
        self.tags.as_ref().map(|tags| {
            tags.values()
                .filter(|t| t.name.ends_with(".sbom"))
                .map(|t| {
                    (
                        Reference::with_tag(
                            registry.to_string(),
                            format!("{}/{}", self.namespace, self.name),
                            t.name.clone(),
                        ),
                        t.size.unwrap_or(u64::MAX),
                    )
                })
                .collect()
        })
    }
}

#[derive(Debug, Default, Deserialize)]
struct Batch {
    repositories: Vec<Repository>,
    next_page: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Tag {
    name: String,
    size: Option<u64>,
}

#[cfg(test)]
mod test {
    use super::*;
    use bytesize::ByteSize;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn walk(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let walker = QuayWalker::new(
            QuayImporter {
                source: "quay.io".into(),
                namespace: Some("redhat-user-workloads".into()),
                size_limit: Some(ByteSize::kib(1).into()),
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
}
