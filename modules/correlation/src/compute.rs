//! Running CPU-heavy work off the async runtime.

use crate::error::Error;
use tokio::task::spawn_blocking;

/// Run CPU-heavy work (e.g. grouping or scoping many rows) on a blocking worker thread, so that it
/// doesn't hold up the async tasks sharing the runtime's threads, like database I/O.
pub async fn on_worker<T, F>(work: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking(work).await?
}
