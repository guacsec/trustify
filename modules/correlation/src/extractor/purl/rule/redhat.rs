//! Red Hat: a version stated as fixed implies that all earlier versions are affected.
//!
//! Red Hat CSAF advisories only list the version fixing a vulnerability, per product stream. A
//! package of the same stream before that version is affected. The stream scoping of the PURL
//! extractor ensures a package isn't judged against the fix of another stream.

use super::{RangeRule, exact_of, low};
use crate::extractor::purl::Candidates;
use sea_orm::sea_query::Expr;
use trustify_entity::status;

/// Publisher namespaces of Red Hat advisories.
const NAMESPACES: &[&str] = &["https://www.redhat.com"];

/// Derives "affected before the fixed version" from the fixed versions of Red Hat advisories.
pub struct RedHatFixed;

impl RangeRule for RedHatFixed {
    fn id(&self) -> &'static str {
        "purl_rh_fixed"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        Candidates {
            // fixed, in an exact version, by Red Hat
            condition: Expr::col((status::Entity, status::Column::Slug))
                .eq("fixed")
                .and(exact_of(NAMESPACES)),
            status: Expr::val("affected").into(),
            // (unbounded, < fixed)
            low_version: Expr::cust("NULL"),
            low_inclusive: Expr::val(false).into(),
            high_version: low(),
            high_inclusive: Expr::val(false).into(),
        }
    }
}
