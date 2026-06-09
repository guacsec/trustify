use crate::{
    runner::{
        context::RunContext,
        progress::{Progress, ProgressInstance},
    },
    server::progress::ServiceProgress,
    service::ImporterService,
};
use std::{
    fmt::Debug,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{Level, instrument};

/// Context for an import run
#[derive(Debug)]
pub struct ServiceRunContext {
    /// The name of the import job
    name: String,
    state: Mutex<CheckCancellation>,
    service: ImporterService,
}

impl ServiceRunContext {
    pub fn new(service: ImporterService, name: String, token: CancellationToken) -> Self {
        Self {
            name: name.clone(),
            state: Mutex::new(CheckCancellation::new(
                service.clone(),
                name,
                Duration::from_secs(20),
                token,
            )),
            service,
        }
    }
}

impl RunContext for ServiceRunContext {
    fn name(&self) -> &str {
        &self.name
    }

    async fn is_canceled(&self) -> bool {
        self.state.lock().await.check().await
    }

    fn progress(&self, _message: String) -> impl Progress + Send + 'static {
        ServiceProgress::new(self.name.clone(), self.service.clone())
    }
}

#[derive(Debug)]
struct CheckCancellation {
    service: ImporterService,
    importer_name: String,
    token: CancellationToken,
    last_check: Instant,
    period: Duration,
}

impl CheckCancellation {
    pub fn new(
        service: ImporterService,
        importer_name: String,
        period: Duration,
        token: CancellationToken,
    ) -> Self {
        Self {
            service,
            importer_name,
            token,
            last_check: Instant::now(),
            period,
        }
    }

    /// Check if the importer was canceled.
    ///
    /// Returns `true` if the reporter was canceled.
    pub async fn check(&mut self) -> bool {
        if !self.token.is_cancelled() && self.last_check.elapsed() > self.period {
            // If we are not canceled yet, and the check expired, we check again.
            // Also, if we encounter an error while checking, we abort, assuming we are canceled.
            if self.perform_check().await.unwrap_or(true) {
                self.token.cancel();
            }
            self.last_check = Instant::now();
        }
        // return the last known state
        self.token.is_cancelled()
    }

    #[instrument(
        skip(self),
        ret(level=Level::DEBUG),
        err(level=Level::INFO),
    )]
    async fn perform_check(&self) -> anyhow::Result<bool> {
        let importer = self.service.read(&self.importer_name).await?;

        // If we have a record, return its state.
        // If we don't have a record, we must have been deleted. Which also means we're canceled.
        Ok(importer
            .map(|importer| importer.value.data.configuration.disabled)
            .unwrap_or(true))
    }
}

pub struct WalkerProgress<P>(pub P)
where
    P: Progress;

impl<P> walker_common::progress::Progress for WalkerProgress<P>
where
    P: Progress,
{
    type Instance = WalkerProgressInstance<P>;

    fn start(&self, work: usize) -> Self::Instance {
        WalkerProgressInstance(self.0.start(work))
    }
}

pub struct WalkerProgressInstance<P>(P::Instance)
where
    P: Progress;

impl<P> walker_common::progress::ProgressBar for WalkerProgressInstance<P>
where
    P: Progress,
{
    async fn increment(&mut self, work: usize) {
        ProgressInstance::increment(&mut self.0, work).await;
    }

    async fn finish(self) {
        ProgressInstance::finish(self.0).await;
    }

    async fn set_message(&mut self, _msg: String) {
        // we don't support that
    }
}
