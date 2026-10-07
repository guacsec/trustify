//! Rules deriving implied version ranges from what advisories state.
//!
//! Ingestion only stores what a document states. Some publishers imply more than they state, e.g.
//! Red Hat only lists the version fixing a vulnerability, implying that earlier versions (of the
//! same stream) are affected. A rule turns such statements into additional candidate ranges,
//! which the PURL extractor matches like stated ones (including the stream scoping), and reports
//! as evidence of the rule's own type.
//!
//! To add a rule, implement [`RangeRule`] in a new module and add it to [`rules`].

mod redhat;
mod suse;

use super::Candidates;
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait,
    sea_query::{Expr, SimpleExpr},
};
use trustify_entity::{advisory, purl_status, version_range};

/// Derives additional, implied version ranges from the statements of an advisory.
pub trait RangeRule: Send + Sync {
    /// Evidence type of matches on derived ranges, e.g. `purl_rh_fixed`.
    fn id(&self) -> &'static str;

    /// Confidence factor, applied on top of the confidence of the stream scoping.
    fn confidence(&self) -> f64;

    /// The derived candidates, as SQL over the stated rows.
    fn candidates(&self) -> Candidates;
}

/// All active rules.
pub fn rules() -> Vec<Box<dyn RangeRule>> {
    vec![
        Box::new(redhat::RedHatFixed),
        Box::new(suse::SuseRecommendedBefore),
        Box::new(suse::SuseRecommended),
        Box::new(suse::SuseAnyVersion),
    ]
}

/// Stated rows of a publisher's advisories, identified by its namespaces (ignoring a trailing
/// `/`).
fn published_by(namespaces: &[&str]) -> SimpleExpr {
    let advisories = advisory::Entity::find()
        .select_only()
        .column(advisory::Column::Id)
        .filter(
            Expr::expr(Expr::cust_with_expr(
                "rtrim($1, '/')",
                Expr::col((advisory::Entity, advisory::Column::PublisherNamespace)),
            ))
            .is_in(namespaces.iter().copied()),
        )
        .into_query();
    purl_status::Column::AdvisoryId.in_subquery(advisories)
}

/// Stated rows of a publisher's advisories, with an exact version (e.g. `fixed` in `1.2-3`).
fn exact_of(namespaces: &[&str]) -> SimpleExpr {
    Expr::expr(low())
        .is_not_null()
        .and(Expr::expr(low()).eq(Expr::col((
            version_range::Entity,
            version_range::Column::HighVersion,
        ))))
        .and(published_by(namespaces))
}

/// Lower bound of the stated range.
fn low() -> SimpleExpr {
    Expr::col((version_range::Entity, version_range::Column::LowVersion)).into()
}
