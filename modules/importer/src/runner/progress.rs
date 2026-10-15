use std::{
    fmt::Display,
    future::Future,
    time::{Duration, Instant},
};
use tokio::runtime::Handle;

pub trait Progress: Send + Sync {
    type Instance: ProgressInstance;

    /// start a new work package
    fn start(&self, work: usize) -> Self::Instance;

    fn message(&self, message: impl Display) -> impl Future<Output = ()>;

    fn message_sync(&self, message: impl Display) {
        Handle::current().block_on(async { self.message(message).await })
    }
}

impl Progress for () {
    type Instance = ();

    fn start(&self, _work: usize) -> Self::Instance {}

    async fn message(&self, _message: impl Display) {}
}

impl ProgressInstance for () {
    async fn increment(&mut self, _work: usize) {}

    async fn finish(self) {}
}

pub trait ProgressInstance: Sized + Send {
    fn tick(&mut self) -> impl Future<Output = ()> + Send {
        self.increment(1)
    }

    /// Sync version of [`tick`].
    ///
    /// **NOTE:** Requires to be called from a tokio context
    fn tick_sync(&mut self) {
        Handle::current().block_on(async { self.tick().await })
    }

    fn increment(&mut self, work: usize) -> impl Future<Output = ()> + Send;

    fn finish(self) -> impl Future<Output = ()> + Send;

    fn finish_sync(self) {
        Handle::current().block_on(async { self.finish().await })
    }
}

/// Report progress to tracing, with a rate limit.
#[derive(Clone, Debug)]
pub struct TracingProgress {
    pub name: String,
    pub period: Duration,
}

pub struct TracingProgressInstance {
    name: String,

    total: usize,
    current: usize,

    start: Instant,
    period: Duration,
    last: Instant,
}

impl Progress for TracingProgress {
    type Instance = TracingProgressInstance;

    fn start(&self, work: usize) -> Self::Instance {
        tracing::info!("Starting: {} - total: {work}", self.name);

        TracingProgressInstance {
            name: self.name.clone(),
            total: work,
            current: 0,
            start: Instant::now(),
            period: self.period,
            // first report with update
            last: Instant::now() - self.period,
        }
    }

    async fn message(&self, message: impl Display) {
        tracing::info!("Progress: {message}");
    }
}

impl ProgressInstance for TracingProgressInstance {
    async fn increment(&mut self, work: usize) {
        self.current += work;
        self.current = self.current.min(self.total);

        if self.last.elapsed() >= self.period {
            self.last = Instant::now();

            let p = self.current as f64 / self.total as f64;
            tracing::info!(
                current = self.current,
                total = self.total,
                percent = p * 100.0,
                "{}: {:.2}% (ETA: {})",
                self.name,
                p * 100.0,
                self.eta()
                    // truncate to seconds
                    .map(|eta| Duration::from_secs(eta.as_secs()))
                    // nice format
                    .map(humantime::Duration::from)
                    // to string ...
                    .map(|eta| eta.to_string())
                    // ... so that we can provide a nice default
                    .unwrap_or_else(|| "?".to_string())
            );
        }
    }

    async fn finish(self) {
        tracing::info!(percent = 100f64, "{}: 100% (complete)", self.name);
    }
}

impl TracingProgressInstance {
    fn eta(&self) -> Option<Duration> {
        if self.current == 0 {
            return None;
        }

        let per_item = self.current as f64 / self.start.elapsed().as_secs_f64();
        let remaining = self.total - self.current;
        let remaining = remaining as f64 / per_item;

        Some(Duration::from_secs_f64(remaining))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct MockProgress {
        updates: Arc<Mutex<Vec<usize>>>,
    }

    struct MockProgressInstance {
        reporter: Arc<Mutex<Vec<usize>>>,
        total: usize,
        current: usize,
    }

    impl MockProgressInstance {
        fn update(&self, progress: f64) {
            self.reporter.lock().push((progress * 100.0) as _);
        }
    }

    impl Progress for MockProgress {
        type Instance = MockProgressInstance;

        fn start(&self, work: usize) -> Self::Instance {
            MockProgressInstance {
                reporter: self.updates.clone(),
                total: work,
                current: 0,
            }
        }

        async fn message(&self, _message: impl Display) {}
    }

    impl ProgressInstance for MockProgressInstance {
        async fn increment(&mut self, work: usize) {
            self.current += work;
            self.current = self.current.min(self.total);

            self.update(self.current as f64 / self.total as f64)
        }

        async fn finish(self) {}
    }

    #[test_log::test(tokio::test)]
    async fn simple() {
        let reporter = MockProgress::default();
        let mut progress = reporter.start(20);

        for _ in 0..10 {
            progress.tick().await;
        }

        progress.finish().await;

        let updates = reporter.updates.lock().clone();

        assert_eq!(updates, vec![5, 10, 15, 20, 25, 30, 35, 40, 45, 50]);
    }
}
