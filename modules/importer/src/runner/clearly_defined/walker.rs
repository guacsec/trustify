use crate::runner::common::Error;
use crate::runner::progress::{Progress, ProgressInstance};
use crate::runner::report::{Phase, ReportBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, LinkedList};
use std::io::{BufRead, Read};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::bytes::Buf;
use trustify_common::db::Database;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};

pub struct ClearlyDefinedWalker<P: Progress + Send + 'static> {
    continuation: ClearlyDefinedItemContinuation,
    source: String,
    ingestor: IngestorService,
    db: Database,
    progress: P,
    report: Arc<Mutex<ReportBuilder>>,
    coordinates_seen_this_run: HashSet<String>,
    client: reqwest::Client,
}

impl<P: Progress + Send + 'static> ClearlyDefinedWalker<P> {
    pub fn new(
        source: impl Into<String>,
        ingestor: IngestorService,
        db: Database,
        report: Arc<Mutex<ReportBuilder>>,
        progress: P,
    ) -> Self {
        Self {
            continuation: Default::default(),
            source: source.into(),
            ingestor,
            db,
            progress,
            report,
            coordinates_seen_this_run: Default::default(),
            client: Default::default(),
        }
    }

    pub fn continuation(mut self, continuation: ClearlyDefinedItemContinuation) -> Self {
        self.continuation = continuation;
        self
    }

    pub async fn run(mut self) -> Result<ClearlyDefinedItemContinuation, Error> {
        let changes = self.client.get(self.changes_index_url()).send().await?;

        let changes = changes.bytes().await?;

        let mut change_notices = Vec::new();

        for line in changes.lines().map_while(Result::ok) {
            change_notices.push(line);
        }

        let filtered_notices = self.continuation.filter(&change_notices);

        let mut progress = self.progress.start(filtered_notices.len());

        let mut high = None;

        for date in filtered_notices {
            if self.load_changes(&date).await.is_ok() {
                high.replace(date);
            }
            progress.tick().await;
        }

        Ok(ClearlyDefinedItemContinuation { high })
    }

    pub async fn load_changes(&mut self, date: &str) -> Result<(), Error> {
        let changes_url = self.changes_url(date);

        let changeset = self
            .client
            .execute(self.client.get(changes_url).build()?)
            .await?;

        let changeset = changeset.bytes().await?;

        for line in changeset.lines().map_while(Result::ok) {
            self.load_coordinate(&line).await?;
        }

        Ok(())
    }

    pub async fn load_coordinate(&mut self, coordinate: &str) -> Result<(), Error> {
        if self.coordinates_seen_this_run.contains(coordinate) {
            return Ok(());
        }

        let url = self.coordinate_url(coordinate);

        let item = self.client.execute(self.client.get(url).build()?).await?;

        let content = item.bytes().await?;
        let mut body = Vec::new();

        content.reader().read_to_end(&mut body)?;

        self.coordinates_seen_this_run
            .insert(coordinate.to_string());

        let mut report = self.report.lock().await;

        let result = self
            .db
            .transaction(async |tx| {
                self.ingestor
                    .ingest(
                        &body,
                        Format::ClearlyDefined,
                        Labels::default(),
                        Some("ClearlyDefined".to_string()),
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await;

        if let Err(err) = result {
            report.add_error(Phase::Upload, coordinate, err.to_string());
        }

        report.tick();

        Ok(())
    }

    fn changes_index_url(&self) -> String {
        let mut url = self.source.clone();
        if !url.ends_with("/") {
            url.push('/');
        }

        url.push_str("changes/index");

        url
    }

    fn changes_url(&self, date: &str) -> String {
        let mut url = self.source.clone();
        if !url.ends_with("/") {
            url.push('/');
        }

        url.push_str("changes/");
        url.push_str(date);

        url
    }

    fn coordinate_url(&self, coordinate: &str) -> String {
        let mut url = self.source.clone();
        if !url.ends_with("/") {
            url.push('/');
        }

        url.push_str(coordinate);

        url
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ClearlyDefinedItemContinuation {
    high: Option<String>,
}

impl ClearlyDefinedItemContinuation {
    fn filter(&self, input: &[String]) -> LinkedList<String> {
        input
            .iter()
            .filter(|e| {
                if let Some(high) = &self.high {
                    **e > *high
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod test {
    use crate::runner::clearly_defined::walker::ClearlyDefinedWalker;
    use crate::runner::report::ReportBuilder;
    use std::sync::Arc;
    use test_context::test_context;
    use test_log::test;
    use tokio::sync::Mutex;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn load_coordinates(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let mut walker = ClearlyDefinedWalker::new(
            "https://clearlydefinedprod.blob.core.windows.net/changes-notifications/",
            ctx.ingestor.clone(),
            ctx.db.clone(),
            Arc::new(Mutex::new(ReportBuilder::new())),
            (),
        );

        walker
            .load_coordinate("crate/cratesio/-/open-enum/0.1.0.json")
            .await?;

        Ok(())
    }
}
