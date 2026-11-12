use crate::health::Check;
use parking_lot::RwLock;
use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Monitor the outcome of some operation.
///
/// The idea of this check is to limit the amount of failing calls, reporting an error when
/// the threshold for a certain amount of time is surpassed.
///
/// The check has an internal counter, which will be incremented for each failure. If the counter
/// is above the threshold, the check is considered failed.
///
/// It is implemented using a leaky-bucket algorithm with a maximum. After each period, the counter
/// will be decremented by the threshold until it reaches zero. The counter will not be incremented
/// beyond the maximum ("threshold" times "number of periods"). This maximum is there to guarantee
/// that the check will always recover after "number of periods" if there are not further errors.
///
/// **NOTE**: Setting the `threshold` to zero will not allow the check to ever recover. A threshold
/// of one will fail the check with the first failure.
///
/// ## Recoding failures
///
/// Failures can be recorded either by just calling [`FailureRate::increment`]. Or by passing through an
/// existing [`Result`] using [`FailureRate::eval`]. It also is possible to wrap an async call using
/// [`FailureRate::guard`].
pub struct FailureRate {
    /// The error message in case of a failure
    error: Cow<'static, str>,
    /// The period
    period: Duration,
    /// The allowed failures per period
    threshold: usize,
    /// The number of periods to consider
    number_of_periods: usize,

    /// The current state
    state: Arc<RwLock<State>>,
}

struct State {
    /// The error counter
    counter: AtomicUsize,
    /// The last trim/check
    last_check: Instant,
}

impl FailureRate {
    pub fn new(
        period: Duration,
        threshold: usize,
        number_of_periods: usize,
        error: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            period,
            threshold,
            error: error.into(),
            number_of_periods,
            state: Arc::new(RwLock::new(State {
                counter: AtomicUsize::new(0),
                last_check: Instant::now(),
            })),
        }
    }

    pub fn handle(&self) -> FailureRateHandle {
        FailureRateHandle {
            state: self.state.clone(),
            max: self.number_of_periods * self.threshold,
        }
    }

    async fn run_at(&self, now: Instant) -> Result<(), Cow<'static, str>> {
        let mut lock = self.state.write();

        // the number of periods to the last update
        let diff = usize::try_from((now - lock.last_check).as_micros() / self.period.as_micros())
            .unwrap_or(usize::MAX);
        if diff > 0 {
            let leak = diff.saturating_mul(self.threshold);
            lock.last_check = now;
            let _ = lock
                .counter
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    Some(current.saturating_sub(leak))
                });
        }

        let current = lock.counter.load(Ordering::SeqCst);

        if current >= self.threshold {
            Err(self.error.clone())
        } else {
            Ok(())
        }
    }
}

impl Check for FailureRate {
    type Error = Cow<'static, str>;

    async fn run(&self) -> Result<(), Self::Error> {
        self.run_at(Instant::now()).await
    }
}

#[derive(Clone)]
pub struct FailureRateHandle {
    /// The current state
    state: Arc<RwLock<State>>,
    /// The total max counter
    max: usize,
}

impl FailureRateHandle {
    /// Run a function and evaluate the result
    pub async fn guard<F, T, E, Fut>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        match f().await {
            Ok(value) => Ok(value),
            Err(err) => {
                self.increment();
                Err(err)
            }
        }
    }

    /// Evaluate the result, increment the counter in case of an error.
    pub fn eval<T, E>(&self, result: Result<T, E>) -> Result<T, E> {
        match result {
            Ok(value) => Ok(value),
            Err(err) => {
                self.increment();
                Err(err)
            }
        }
    }

    /// Increment the counter by one.
    pub fn increment(&self) {
        let lock = self.state.read();

        // increment if we are below max
        let _ = lock
            .counter
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current < self.max {
                    Some(current + 1)
                } else {
                    None
                }
            });
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_ok() {
        let check = FailureRate::new(Duration::from_secs(1), 5, 5, "mock error");
        let handle = check.handle();

        let now = { check.state.read().last_check };

        // one success, one failure, should be below the threshold

        let _ = handle.guard(|| async { Ok::<_, ()>(()) }).await;
        let _ = handle.guard(|| async { Err::<(), _>(()) }).await;

        // check at t = 0s
        let r = check.run_at(now).await;
        assert_eq!(r, Ok(()));
    }

    #[tokio::test]
    async fn test_fail() {
        let check = FailureRate::new(Duration::from_secs(1), 5, 5, "mock error");
        let handle = check.handle();

        let mut now = { check.state.read().last_check };

        // ten errors, should make it fail
        for _ in 0..10 {
            let _ = handle.guard(|| async { Err::<(), _>(()) }).await;
        }

        // should fail for t = 0s..1s
        for i in 0..2 {
            let r = check.run_at(now).await;
            assert_eq!(r, Err("mock error".into()), "should fail a t = {i}s");
            now += Duration::from_secs(1);
        }

        // should pass for t = 2s..
        let r = check.run_at(now).await;
        assert_eq!(r, Ok(()));
    }

    #[tokio::test]
    async fn test_fail_max() {
        let check = FailureRate::new(Duration::from_secs(1), 5, 5, "mock error");
        let handle = check.handle();

        let mut now = { check.state.read().last_check };

        // 100 errors, should make it fail
        for _ in 0..100 {
            let _ = handle.guard(|| async { Err::<(), _>(()) }).await;
        }

        // should fail for t = 0s..5s
        for i in 0..5 {
            let r = check.run_at(now).await;
            assert_eq!(r, Err("mock error".into()), "should fail a t = {i}s");
            now += Duration::from_secs(1);
        }

        // should pass for t = 5s.., as we had a cap of 5 * 5
        let r = check.run_at(now).await;
        assert_eq!(r, Ok(()));
    }

    #[tokio::test]
    async fn test_fail_max_skip() {
        let check = FailureRate::new(Duration::from_secs(1), 5, 5, "mock error");
        let handle = check.handle();

        let now = { check.state.read().last_check };

        // 100 errors, should make it fail
        for _ in 0..100 {
            let _ = handle.guard(|| async { Err::<(), _>(()) }).await;
        }

        // should fail for t = 0s
        let r = check.run_at(now).await;
        assert_eq!(r, Err("mock error".into()));

        // should pass for t = 20s, without intermediate checks
        let r = check.run_at(now + Duration::from_secs(20)).await;
        assert_eq!(r, Ok(()));
    }
}
