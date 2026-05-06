use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use moka::future::Cache;
use opentelemetry::{global, metrics::Counter};
use std::{sync::Arc, time::Duration};

use crate::error::ErrorInformation;

/// The requested pagination limit exceeds the configured maximum.
#[derive(Clone, Debug, thiserror::Error)]
#[error("pagination limit exceeds maximum of {max_limit}")]
pub struct LimitError {
    pub max_limit: u64,
}

impl ResponseError for LimitError {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::BadRequest()
            .append_header(("X-Pagination-Max-Limit", self.max_limit.to_string()))
            .json(ErrorInformation {
                error: "LimitExceeded".into(),
                message: format!(
                    "requested pagination limit exceeds the maximum of {}",
                    self.max_limit
                ),
                details: None,
            })
    }
}

pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Caches pagination total counts to avoid expensive COUNT queries on repeated pages.
#[derive(Clone, Debug)]
pub struct PaginationCache {
    cache: Arc<Cache<String, u64>>,
    total: Counter<u64>,
    misses: Counter<u64>,
    max_limit: u64,
}

impl PaginationCache {
    /// Create a new cache with the given TTL for total-count entries and an optional maximum limit.
    pub fn new(ttl: Duration, max_limit: u64) -> Self {
        let meter = global::meter("PaginationCache");
        Self {
            cache: Arc::new(Cache::builder().time_to_live(ttl).build()),
            total: meter.u64_counter("cache_total").build(),
            misses: meter.u64_counter("cache_miss").build(),
            max_limit,
        }
    }

    /// Create a cache with zero TTL and no maximum limit, intended for use in tests
    /// where mutations between requests must be immediately visible.
    pub fn for_test() -> Self {
        Self::new(Duration::ZERO, 0)
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

    /// Check that the given limit does not exceed the configured maximum.
    /// Returns the limit unchanged, or an error if it exceeds the maximum.
    pub(crate) fn check_limit(&self, limit: u64) -> Result<u64, LimitError> {
        if self.max_limit > 0 && limit > self.max_limit {
            Err(LimitError {
                max_limit: self.max_limit,
            })
        } else {
            Ok(limit)
        }
    }

    /// Return the configured maximum pagination limit (0 = no maximum).
    pub fn max_limit(&self) -> u64 {
        self.max_limit
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

    /// Maximum allowed limit for pagination queries (0 = no maximum)
    #[arg(
        id = "pagination-max-limit",
        long,
        env = "TRUSTD_PAGINATION_MAX_LIMIT",
        default_value_t = 1000
    )]
    pub max_limit: u64,
}

impl PaginationConfig {
    /// Build a [`PaginationCache`] from this configuration.
    pub fn into_cache(self) -> PaginationCache {
        PaginationCache::new(*self.cache_ttl, self.max_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, body::MessageBody, test as actix_test, web};
    use rstest::rstest;

    /// Limits pass through when no maximum is configured.
    #[test]
    fn check_limit_no_max() {
        let cache = PaginationCache::new(Duration::ZERO, 0);
        assert_eq!(cache.check_limit(100).unwrap(), 100);
        assert_eq!(cache.check_limit(0).unwrap(), 0);
    }

    /// Limits at or below the maximum pass; exceeding it returns an error.
    #[test]
    fn check_limit_with_max() {
        let cache = PaginationCache::new(Duration::ZERO, 50);
        assert_eq!(cache.check_limit(25).unwrap(), 25);
        assert_eq!(cache.check_limit(50).unwrap(), 50);
        assert!(cache.check_limit(100).is_err());
    }

    /// A zero limit is always allowed, even when a maximum is set.
    #[test]
    fn check_limit_zero_unchanged() {
        let cache = PaginationCache::new(Duration::ZERO, 50);
        assert_eq!(cache.check_limit(0).unwrap(), 0);
    }

    /// Handler that always returns a LimitError for the given max_limit.
    async fn limit_error_handler(max_limit: web::Path<u64>) -> Result<HttpResponse, LimitError> {
        Err(LimitError {
            max_limit: max_limit.into_inner(),
        })
    }

    /// Verify the HTTP error response: status 400, X-Pagination-Max-Limit header, and JSON body.
    #[rstest]
    #[case(50)]
    #[case(100)]
    #[case(1000)]
    #[actix_web::test]
    async fn limit_error_response(#[case] max_limit: u64) {
        let app = actix_test::init_service(
            App::new().route("/test/{max_limit}", web::get().to(limit_error_handler)),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri(&format!("/test/{max_limit}"))
            .to_request();
        let response = actix_test::call_service(&app, req).await;

        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);

        let header = response
            .headers()
            .get("X-Pagination-Max-Limit")
            .expect("missing X-Pagination-Max-Limit header");
        assert_eq!(header.to_str().unwrap(), max_limit.to_string());

        let body = response.into_body().try_into_bytes().unwrap();
        let info: ErrorInformation =
            serde_json::from_slice(&body).expect("response body should be valid JSON");
        assert_eq!(info.error, "LimitExceeded");
        assert!(
            info.message.contains(&max_limit.to_string()),
            "message should contain the max limit value"
        );
    }
}
