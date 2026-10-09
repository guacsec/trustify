//! Rules deriving implied version ranges from what advisories state.
//!
//! Ingestion only stores what a document states. Some publishers imply more than they state, e.g.
//! Red Hat only lists the version fixing a vulnerability, implying that earlier versions (of the
//! same stream) are affected. A rule turns such statements into additional candidate ranges,
//! which the PURL extractor matches like stated ones (including the stream scoping), and reports
//! as evidence of the rule's own type.
//!
//! Whether a rule applies can depend on the correlation options of a publisher (see
//! [`crate::service::option`]), e.g. reading versionless PURLs as all versions. Such evidence
//! records the option which enabled it.
//!
//! To add a rule, implement [`RangeRule`] in a new module and add it to [`rules`].

mod any_version;
mod redhat;
mod suse;
mod vls;

use super::Candidates;
use crate::{error::Error, model::EnabledBy};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait,
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

    /// Whether the derived candidates only apply to a node in the assertion's context (product).
    fn requires_context(&self) -> bool {
        false
    }

    /// The option which enabled a candidate of an advisory with the given publisher namespace,
    /// `None` if the rule doesn't depend on an option.
    fn enabled_by(&self, publisher_namespace: Option<&str>) -> Option<EnabledBy> {
        let _ = publisher_namespace;
        None
    }
}

/// All active rules, with the current correlation options.
pub async fn rules<C: ConnectionTrait>(connection: &C) -> Result<Vec<Box<dyn RangeRule>>, Error> {
    Ok(vec![
        Box::new(redhat::RedHatFixed),
        Box::new(suse::SuseRecommendedBefore),
        Box::new(suse::SuseRecommended),
        Box::new(any_version::AnyVersion::load(connection).await?),
        Box::new(vls::VlsRange),
    ])
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
