use crate::runner::progress::Progress;
use std::{fmt::Debug, future::Future};
use tokio::runtime::Handle;

pub trait RunContext: Debug + Send {
    /// Get the name of the import job
    fn name(&self) -> &str;

    /// Check if the run is canceled.
    ///
    /// This is a cooperative way to check if the job needs to be terminated.
    fn is_canceled(&self) -> impl Future<Output = bool>;

    /// A sync version of [`Self::is_canceled`].
    ///
    /// **NOTE:** Requires to be called from a Tokio context.
    fn is_canceled_sync(&self) -> bool {
        Handle::current().block_on(async { self.is_canceled().await })
    }

    fn check_canceled_sync<E, F>(&self, f: F) -> Result<(), E>
    where
        F: FnOnce() -> E,
    {
        match self.is_canceled_sync() {
            true => Err(f()),
            false => Ok(()),
        }
    }

    fn check_canceled<E, F>(&self, f: F) -> impl Future<Output = Result<(), E>>
    where
        F: FnOnce() -> E,
    {
        async {
            match self.is_canceled().await {
                true => Err(f()),
                false => Ok(()),
            }
        }
    }

    fn progress(&self, #[allow(unused)] message: String) -> impl Progress + Send + 'static {}
}
