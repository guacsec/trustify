//! Client side token handling (acquire and refresh)

mod error;
mod inject;
mod provider;

pub use error::*;
pub use inject::*;
pub use provider::*;

use time::{Duration, OffsetDateTime};

/// Check if something expired or expires soon.
pub trait Expires {
    /// Check if the resource expires before the duration elapsed.
    fn expires_before(&self, duration: Duration) -> bool;
}

impl Expires for openid::TemporalBearerGuard {
    fn expires_before(&self, duration: Duration) -> bool {
        match self.expires_at() {
            Some(expires) => {
                // Read the upstream timestamp without restricting it to time's
                // smaller calendar range (an issuer can return a distant expiry).
                let expires = i128::from(expires.timestamp()) * 1_000_000_000
                    + i128::from(expires.timestamp_subsec_nanos());
                expires - OffsetDateTime::now_utc().unix_timestamp_nanos()
                    <= duration.whole_nanoseconds()
            }
            None => false,
        }
    }
}
