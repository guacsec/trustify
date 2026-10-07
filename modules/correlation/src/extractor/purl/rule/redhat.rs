//! Red Hat: a version stated as fixed implies that all earlier versions are affected.
//!
//! Red Hat CSAF advisories only list the version fixing a vulnerability, per product stream. A
//! package of the same stream before that version is affected. The stream scoping of the PURL
//! extractor ensures a package isn't judged against the fix of another stream.

use super::RangeRule;
use crate::extractor::purl::Candidates;
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait,
    sea_query::{Expr, SimpleExpr},
};
use trustify_entity::{advisory, purl_status, status, version_range};

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
        let low = || -> SimpleExpr {
            Expr::col((version_range::Entity, version_range::Column::LowVersion)).into()
        };
        let high = Expr::col((version_range::Entity, version_range::Column::HighVersion));

        let redhat_advisories = advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filter(
                Expr::expr(Expr::cust_with_expr(
                    "rtrim($1, '/')",
                    Expr::col((advisory::Entity, advisory::Column::PublisherNamespace)),
                ))
                .is_in(NAMESPACES.iter().copied()),
            )
            .into_query();

        Candidates {
            // fixed, in an exact version, by Red Hat
            condition: Expr::col((status::Entity, status::Column::Slug))
                .eq("fixed")
                .and(Expr::expr(low()).is_not_null())
                .and(Expr::expr(low()).eq(high))
                .and(purl_status::Column::AdvisoryId.in_subquery(redhat_advisories)),
            status: Expr::val("affected").into(),
            // (unbounded, < fixed)
            low_version: Expr::cust("NULL"),
            low_inclusive: Expr::val(false).into(),
            high_version: low(),
            high_inclusive: Expr::val(false).into(),
        }
    }
}
