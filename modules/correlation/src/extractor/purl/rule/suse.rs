//! SUSE: a recommended version is the fix of its codestream, and versionless statements cover all
//! versions.
//!
//! SUSE CSAF VEX documents don't state `fixed`, but list the package version to update to as
//! `recommended`, per product. A package of the same codestream before that version is affected,
//! and from that version on it is fixed. The codestream scoping of the PURL extractor ensures a
//! package isn't judged against the fix of another codestream (e.g. SLE 15 SP7 or Tumbleweed for
//! an SLE 15 SP6 package).
//!
//! Statements about all versions of a package in a product (e.g. `known_not_affected`) use a PURL
//! without a version (`pkg:rpm/suse/openssl-3@`), which is stored as the exact, empty version. As
//! the product isn't part of the match yet, those apply to the package in any product.

use super::{RangeRule, exact_of, low, published_by};
use crate::extractor::purl::Candidates;
use sea_orm::sea_query::{Expr, SimpleExpr};
use trustify_entity::{status, version_range};

/// Publisher namespaces of SUSE advisories.
const NAMESPACES: &[&str] = &["https://www.suse.com"];

/// The `recommended` rows of SUSE advisories, with an exact version.
fn recommended() -> SimpleExpr {
    Expr::col((status::Entity, status::Column::Slug))
        .eq("recommended")
        .and(exact_of(NAMESPACES))
}

/// Derives "affected before the recommended version" from SUSE advisories.
pub struct SuseRecommendedBefore;

impl RangeRule for SuseRecommendedBefore {
    fn id(&self) -> &'static str {
        "purl_suse_recommended_before"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        Candidates {
            condition: recommended(),
            status: Expr::val("affected").into(),
            // (unbounded, < recommended)
            low_version: Expr::cust("NULL"),
            low_inclusive: Expr::val(false).into(),
            high_version: low(),
            high_inclusive: Expr::val(false).into(),
        }
    }
}

/// Derives "fixed from the recommended version on" from SUSE advisories.
pub struct SuseRecommended;

impl RangeRule for SuseRecommended {
    fn id(&self) -> &'static str {
        "purl_suse_recommended"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        Candidates {
            condition: recommended(),
            status: Expr::val("fixed").into(),
            // [recommended, unbounded)
            low_version: low(),
            low_inclusive: Expr::val(true).into(),
            high_version: Expr::cust("NULL"),
            high_inclusive: Expr::val(false).into(),
        }
    }
}

/// Derives "all versions" from the versionless statements of SUSE advisories.
pub struct SuseAnyVersion;

impl RangeRule for SuseAnyVersion {
    fn id(&self) -> &'static str {
        "purl_suse_any_version"
    }

    /// Lower, as the statement is about a product, which isn't considered yet.
    fn confidence(&self) -> f64 {
        0.7
    }

    fn candidates(&self) -> Candidates {
        let high = Expr::col((version_range::Entity, version_range::Column::HighVersion));
        Candidates {
            // the exact, empty version, by SUSE
            condition: Expr::expr(low())
                .eq("")
                .and(high.eq(""))
                .and(published_by(NAMESPACES)),
            status: Expr::col((status::Entity, status::Column::Slug)).into(),
            // (unbounded, unbounded)
            low_version: Expr::cust("NULL"),
            low_inclusive: Expr::val(false).into(),
            high_version: Expr::cust("NULL"),
            high_inclusive: Expr::val(false).into(),
        }
    }
}
