use moka::future::Cache;
use opentelemetry::{global, metrics::Counter};
use std::{sync::Arc, time::Duration};

pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Caches pagination total counts to avoid expensive COUNT queries on repeated pages.
#[derive(Clone, Debug)]
pub struct PaginationCache {
    cache: Arc<Cache<String, u64>>,
    total: Counter<u64>,
    misses: Counter<u64>,
}

impl PaginationCache {
    /// Create a new cache with the given TTL for total-count entries.
    pub fn new(ttl: Duration) -> Self {
        let meter = global::meter("PaginationCache");
        Self {
            cache: Arc::new(Cache::builder().time_to_live(ttl).build()),
            total: meter.u64_counter("cache_total").build(),
            misses: meter.u64_counter("cache_miss").build(),
        }
    }

    /// Create a cache with zero TTL, intended for use in tests where mutations
    /// between requests must be immediately visible.
    pub fn for_test() -> Self {
        Self::new(Duration::ZERO)
    }

    /// Return a cached total count, computing it at most once for concurrent requests with the same key.
    pub async fn cached_total(
        &self,
        key: String,
        compute: impl AsyncFnOnce() -> Result<u64, sea_orm::DbErr>,
    ) -> Result<u64, sea_orm::DbErr> {
        self.total.add(1, &[]);
        let misses = self.misses.clone();
        self.cache
            .try_get_with(key, async {
                misses.add(1, &[]);
                compute().await
            })
            .await
            .map_err(|e| sea_orm::DbErr::Custom(e.to_string()))
    }
}

/// CLI/env configuration for the pagination cache.
#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Pagination")]
pub struct PaginationConfig {
    /// TTL for cached pagination total counts (humantime, e.g. "60s", "5m")
    #[arg(
        id = "pagination-cache-ttl",
        long,
        env = "TRUSTD_PAGINATION_TOTAL_CACHE_TTL",
        default_value = "60s"
    )]
    pub cache_ttl: humantime::Duration,
}

impl PaginationConfig {
    /// Build a [`PaginationCache`] from this configuration.
    pub fn into_cache(self) -> PaginationCache {
        PaginationCache::new(*self.cache_ttl)
    }
}
