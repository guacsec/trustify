use crate::health::Check;
use anyhow::Context;
use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::select;
use tokio::sync::oneshot;
use tokio::task::LocalSet;
use tokio::time::{MissedTickBehavior, interval};

pub struct Local<T = ()> {
    error: Cow<'static, str>,
    state: Arc<AtomicBool>,
    _handle: T,
}

pub struct Shutdown(Option<oneshot::Sender<()>>);

impl Drop for Shutdown {
    fn drop(&mut self) {
        if let Some(shutdown) = self.0.take() {
            let _ = shutdown.send(());
        }
    }
}

pub struct LocalState(Arc<AtomicBool>);

impl LocalState {
    fn set(&self, value: bool) {
        self.0.store(value, Ordering::Release);
    }
}

impl<T> Local<T> {
    pub fn spawn<F, Fut>(error: impl Into<Cow<'static, str>>, f: F) -> anyhow::Result<Local<()>>
    where
        F: FnOnce(LocalState) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let state = Arc::new(AtomicBool::new(false));
        let error: Cow<'static, str> = error.into();

        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to start dedicated check runtime")?;

        {
            let state = state.clone();
            let error = error.clone();
            std::thread::spawn(move || {
                let local = LocalSet::new();
                {
                    let state = state.clone();
                    local.spawn_local(f(LocalState(state)));
                }

                rt.block_on(local);

                log::warn!(
                    "health check future returned, will report failure from now on: {error}"
                );

                // if the check loop ends, the check defaults to false
                state.store(false, Ordering::Release);
            });
        }

        Ok(Local {
            error,
            state,
            _handle: (),
        })
    }

    fn handle<U>(self, handle: U) -> Local<U> {
        Local {
            state: self.state,
            error: self.error,
            _handle: handle,
        }
    }
}

impl Local<Shutdown> {
    pub fn spawn_periodic<F, Fut>(
        error: impl Into<Cow<'static, str>>,
        period: Duration,
        f: F,
    ) -> anyhow::Result<Local<Shutdown>>
    where
        F: Fn() -> Fut + Sync + Send + 'static,
        Fut: Future<Output = bool>,
    {
        let (tx, mut rx) = oneshot::channel::<()>();

        Ok(Self::spawn(error, move |state| async move {
            let mut interval = interval(period);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                select! {
                    _ = interval.tick() => {
                        let result = f().await;
                        state.set(result);
                    }
                    _ = &mut rx => {
                        log::info!("received shutdown signal");
                        break;
                    }
                }
            }
        })?
        .handle(Shutdown(Some(tx))))
    }
}

impl<T> Check for Local<T>
where
    T: Send + Sync,
{
    type Error = Cow<'static, str>;

    async fn run(&self) -> Result<(), Self::Error> {
        match self.state.as_ref().load(Ordering::Acquire) {
            true => Ok(()),
            false => Err(self.error.clone()),
        }
    }
}
