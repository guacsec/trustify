//! SUSE: a recommended version is the fix of its codestream.
//!
//! SUSE CSAF VEX documents don't state `fixed`, but list the package version to update to as
//! `recommended`, per product. A package of the same codestream before that version is affected,
//! and from that version on it is fixed. The codestream scoping of the PURL extractor ensures a
//! package isn't judged against the fix of another codestream (e.g. SLE 15 SP7 or Tumbleweed for
//! an SLE 15 SP6 package).
//!
//! Statements about all versions of a package in a product use a versionless PURL
//! (`pkg:rpm/suse/openssl-3@`), see [`super::any_version`].

use super::{RangeRule, exact_of, low};
use crate::extractor::purl::{Candidates, stated_scheme};
use sea_orm::sea_query::{Expr, ExprTrait, SimpleExpr};
use trustify_entity::status;

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
            status: Expr::val("affected"),
            scheme: stated_scheme(),
            // (unbounded, < recommended)
            low_version: Expr::cust("NULL"),
            low_inclusive: Expr::val(false),
            high_version: low(),
            high_inclusive: Expr::val(false),
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
            status: Expr::val("fixed"),
            scheme: stated_scheme(),
            // [recommended, unbounded)
            low_version: low(),
            low_inclusive: Expr::val(true),
            high_version: Expr::cust("NULL"),
            high_inclusive: Expr::val(false),
        }
    }
}
