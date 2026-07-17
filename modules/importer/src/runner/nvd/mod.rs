use crate::{
    model::NvdImporter,
    runner::{
        RunOutput,
        context::RunContext,
        progress::{Progress, ProgressInstance},
        report::{Phase, ReportBuilder, ScannerError},
    },
};
use std::collections::{BTreeSet, HashMap};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::{
    graph::Graph,
    service::{Cache, Format, IngestorService, advisory::nvd::schema::NvdYearFeed},
};

/// The earliest CVE year published by NVD.
const NVD_FIRST_YEAR: u16 = 1999;

impl super::ImportRunner {
    #[instrument(skip(self, context), err(level=tracing::Level::INFO))]
    pub async fn run_once_nvd(
        &self,
        context: impl RunContext + 'static,
        nvd: NvdImporter,
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor =
            IngestorService::new(Graph::new(), self.storage.clone(), self.analysis.clone());

        let mut report = ReportBuilder::new();

        // Per-year sha256 of the last successfully ingested feed asset. A year
        // is re-ingested only when its `.meta` sha256 differs, so steady-state
        // runs transfer just the changed years.
        let mut state: HashMap<u16, String> =
            serde_json::from_value(continuation).unwrap_or_default();

        let base = format!(
            "{}/releases/latest/download",
            nvd.source.trim_end_matches('/')
        );

        let client = reqwest::Client::builder()
            .user_agent("trustify-nvd-importer")
            .build()
            .map_err(|err| ScannerError::Critical(err.into()))?;

        let years = resolve_years(&nvd);

        let progress = context.progress(format!("Import NVD: {}", nvd.source));
        let mut instance = progress.start(years.len());

        for year in years {
            if context.is_canceled().await {
                break;
            }

            progress.message(format!("NVD {year}")).await;

            if let Err(err) = self
                .ingest_year(&client, &ingestor, &base, year, &mut state, &mut report)
                .await
            {
                // Record and continue: one bad year must not abort the rest, and
                // its state is left untouched so it retries next run.
                tracing::warn!("Failed to process NVD year {year}: {err}");
                report.add_error(Phase::Retrieval, format!("CVE-{year}"), err.to_string());
            }

            instance.tick().await;
        }

        instance.finish().await;

        Ok(RunOutput {
            report: report.build(),
            continuation: serde_json::to_value(state).ok(),
        })
    }

    /// Downloads, decompresses and ingests a single year's feed asset, skipping
    /// the work when the asset's sha256 is unchanged since the last run.
    async fn ingest_year(
        &self,
        client: &reqwest::Client,
        ingestor: &IngestorService,
        base: &str,
        year: u16,
        state: &mut HashMap<u16, String>,
        report: &mut ReportBuilder,
    ) -> anyhow::Result<()> {
        let asset = format!("CVE-{year}.json.xz");

        // 1. Cheap change check via the `.meta` sidecar.
        let sha256 = fetch_meta_sha256(client, &format!("{base}/CVE-{year}.meta")).await?;
        if let (Some(sha256), Some(prev)) = (&sha256, state.get(&year))
            && sha256 == prev
        {
            tracing::info!("NVD {year}: unchanged (sha256 {sha256}), skipping");
            return Ok(());
        }

        // 2. Download + decompress the year feed.
        let compressed = client
            .get(format!("{base}/{asset}"))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;

        let decompressed = walker_common::compression::decompress(compressed, &asset)?;
        let feed: NvdYearFeed = serde_json::from_slice(decompressed.as_ref())?;

        // 3. Ingest each CVE record, one transaction per record (matches the
        //    CVE importer). The raw fragment bytes are handed straight to the
        //    NVD loader.
        let count = feed.cve_items.len();
        for item in &feed.cve_items {
            let data = item.get().as_bytes();
            let result = self
                .db
                .transaction(async |tx| {
                    ingestor
                        .ingest(
                            data,
                            Format::NVD,
                            Labels::new().add("source", "nvd").add("file", &asset),
                            None,
                            Cache::Skip,
                            tx,
                        )
                        .await
                })
                .await;

            match result {
                Ok(_) => report.tick(),
                Err(err) => report.add_error(Phase::Upload, asset.clone(), err.to_string()),
            }
        }

        tracing::info!("NVD {year}: ingested {count} records");

        // 4. Record the sha256 so the next run can skip this year if unchanged.
        if let Some(sha256) = sha256 {
            state.insert(year, sha256);
        }

        Ok(())
    }
}

/// The set of years to process: the explicit `years` set if provided, otherwise
/// `start_year` (default 1999) through the current UTC year, inclusive.
///
/// A non-empty `years` takes precedence; `start_year` is ignored in that case.
fn resolve_years(nvd: &NvdImporter) -> BTreeSet<u16> {
    if !nvd.years.is_empty() {
        if nvd.start_year.is_some() {
            tracing::warn!(
                "NVD importer has both `years` and `startYear` configured; using the explicit `years` set and ignoring `startYear`"
            );
        }
        return nvd.years.iter().copied().collect();
    }

    let current = OffsetDateTime::now_utc().year().clamp(0, u16::MAX as i32) as u16;
    let start = nvd.start_year.unwrap_or(NVD_FIRST_YEAR);
    (start..=current).collect()
}

/// Parses the `sha256:` line from a `.meta` sidecar. Returns `None` if the field
/// is absent (in which case the year is always re-ingested).
async fn fetch_meta_sha256(client: &reqwest::Client, url: &str) -> anyhow::Result<Option<String>> {
    let meta = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    Ok(meta.lines().find_map(|line| {
        line.strip_prefix("sha256:")
            .map(|value| value.trim().to_string())
    }))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::runner::ImportRunner;
    use liblzma::write::XzEncoder;
    use std::io::Write;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::ReadWrite;
    use trustify_test_context::TrustifyContext;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn importer(years: &[u16], start_year: Option<u16>, source: &str) -> NvdImporter {
        NvdImporter {
            common: Default::default(),
            source: source.to_string(),
            years: years.iter().copied().collect(),
            start_year,
        }
    }

    #[test]
    fn resolve_years_explicit_set_wins() {
        let nvd = importer(&[2001, 2003], Some(1999), "");
        assert_eq!(
            resolve_years(&nvd).into_iter().collect::<Vec<_>>(),
            vec![2001, 2003]
        );
    }

    #[test]
    fn resolve_years_start_year_through_current() {
        let current = OffsetDateTime::now_utc().year() as u16;
        let nvd = importer(&[], Some(current - 2), "");
        assert_eq!(
            resolve_years(&nvd).into_iter().collect::<Vec<_>>(),
            vec![current - 2, current - 1, current]
        );
    }

    #[test]
    fn resolve_years_defaults_to_first_nvd_year() {
        let nvd = importer(&[], None, "");
        let years = resolve_years(&nvd);
        assert_eq!(years.first(), Some(&NVD_FIRST_YEAR));
        assert_eq!(
            years.last(),
            Some(&(OffsetDateTime::now_utc().year() as u16))
        );
    }

    /// xz-compress a per-year feed envelope around the existing NVD test record.
    fn feed_asset() -> Vec<u8> {
        let feed = format!(
            r#"{{"cve_items": [{}]}}"#,
            include_str!("../../../../../etc/test-data/nvd/CVE-2099-1000.json")
        );

        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(feed.as_bytes()).expect("xz encode");
        encoder.finish().expect("xz finish")
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_mock_nvd(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        // Start a background HTTP server on a random local port
        let nvd = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/releases/latest/download/CVE-2099.meta"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("lastModifiedDate:2099-01-05T12:30:00+00:00\nsha256:0000000000000000000000000000000000000000000000000000000000000000\n"),
            )
            .mount(&nvd)
            .await;
        Mock::given(method("GET"))
            .and(path("/releases/latest/download/CVE-2099.json.xz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(feed_asset()))
            .mount(&nvd)
            .await;

        let runner = ImportRunner {
            db: ReadWrite::new(ctx.db.clone()),
            storage: ctx.storage.clone().into(),
            working_dir: None,
            analysis: None,
        };

        // First run: the year is new, so the feed is downloaded and ingested.
        let output = runner
            .run_once_nvd(
                (),
                importer(&[2099], None, &nvd.uri()),
                serde_json::Value::Null,
            )
            .await?;

        assert_eq!(output.report.number_of_items, 1);
        assert!(
            output.report.messages.is_empty(),
            "{:?}",
            output.report.messages
        );

        let continuation = output.continuation.expect("continuation state");
        let state: HashMap<u16, String> = serde_json::from_value(continuation.clone())?;
        assert_eq!(
            state.get(&2099).map(String::as_str),
            Some("0000000000000000000000000000000000000000000000000000000000000000")
        );

        // Second run with the returned continuation: the `.meta` sha256 is
        // unchanged, so the year is skipped without re-ingesting.
        let output = runner
            .run_once_nvd(
                (),
                importer(&[2099], None, &nvd.uri()),
                continuation.clone(),
            )
            .await?;

        assert_eq!(output.report.number_of_items, 0);
        assert!(
            output.report.messages.is_empty(),
            "{:?}",
            output.report.messages
        );
        assert_eq!(output.continuation, Some(continuation));

        Ok(())
    }
}
