//! CSAF: the meaning of the product statuses stating a single version as a version range.
//!
//! CSAF states `first_fixed`, `first_affected` and `last_affected` for a version, meaning a
//! boundary of the versions of a release which are fixed or affected. Ingestion stores them as
//! stated, as the exact version. These rules derive the range they mean. The stream scoping of
//! the PURL extractor ensures a version is only compared within its own stream.

use super::{RangeRule, exact_status, low};
use crate::extractor::purl::{Candidates, stated_scheme};
use sea_orm::sea_query::{Expr, SimpleExpr};

/// Unbounded side of a range.
fn unbounded() -> SimpleExpr {
    Expr::cust("NULL")
}

/// From the stated version on: `[X, unbounded)`.
fn from(slug: &str, status: &str) -> Candidates {
    Candidates {
        condition: exact_status(slug),
        status: Expr::val(status).into(),
        scheme: stated_scheme(),
        low_version: low(),
        low_inclusive: Expr::val(true).into(),
        high_version: unbounded(),
        high_inclusive: Expr::val(false).into(),
    }
}

/// Up to the stated version: `(unbounded, X)`, or `(unbounded, X]` if inclusive.
fn up_to(slug: &str, status: &str, inclusive: bool) -> Candidates {
    Candidates {
        condition: exact_status(slug),
        status: Expr::val(status).into(),
        scheme: stated_scheme(),
        low_version: unbounded(),
        low_inclusive: Expr::val(false).into(),
        high_version: low(),
        high_inclusive: Expr::val(inclusive).into(),
    }
}

/// `first_fixed`: fixed from that version on.
pub struct FirstFixed;

impl RangeRule for FirstFixed {
    fn id(&self) -> &'static str {
        "purl_first_fixed"
    }

    /// The stated meaning.
    fn confidence(&self) -> f64 {
        1.0
    }

    fn candidates(&self) -> Candidates {
        from("first_fixed", "fixed")
    }
}

/// `first_fixed`: the versions before aren't fixed, so they are affected.
pub struct FirstFixedBefore;

impl RangeRule for FirstFixedBefore {
    fn id(&self) -> &'static str {
        "purl_first_fixed_before"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        up_to("first_fixed", "affected", false)
    }
}

/// `first_affected`: affected from that version on (until a fix, which wins the verdict).
pub struct FirstAffected;

impl RangeRule for FirstAffected {
    fn id(&self) -> &'static str {
        "purl_first_affected"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        from("first_affected", "affected")
    }
}

/// `last_affected`: affected up to and including that version.
pub struct LastAffected;

impl RangeRule for LastAffected {
    fn id(&self) -> &'static str {
        "purl_last_affected"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        up_to("last_affected", "affected", true)
    }
}
