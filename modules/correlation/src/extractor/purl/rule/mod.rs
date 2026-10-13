//! Rules deriving implied version ranges from what advisories state.
//!
//! Ingestion only stores what a document states. Some statements mean a range, although they
//! state a single version (e.g. CSAF `first_fixed`), and some publishers imply more than they
//! state, e.g. Red Hat only lists the version fixing a vulnerability, implying that earlier
//! versions (of the same stream) are affected. A rule turns such statements into candidate ranges,
//! which the PURL extractor matches like stated ones (including the stream scoping), and reports
//! as evidence of the rule's own type.
//!
//! Whether a rule applies can depend on the correlation options of a publisher (see
//! [`crate::service::option`]), e.g. reading versionless PURLs as all versions. Such evidence
//! records the option which enabled it.
//!
//! To add a rule, implement [`RangeRule`] in a new module and add it to [`rules`].

mod any_version;
mod csaf;
mod suse;
mod vls;

use super::Candidates;
use crate::{error::Error, model::EnabledBy};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait,
    sea_query::{Expr, ExprTrait, SimpleExpr},
};
use serde_json::Value;
use trustify_entity::{
    advisory,
    correlation_option::{self, CorrelationOptionKey},
    purl_status, status, version_range,
};

/// Derives additional, implied version ranges from the statements of an advisory.
pub trait RangeRule: Send + Sync {
    /// Evidence type of matches on derived ranges, e.g. `purl_first_fixed`.
    fn id(&self) -> &'static str;

    /// Confidence factor, applied on top of the confidence of the stream scoping.
    fn confidence(&self) -> f64;

    /// The derived candidates, as SQL over the stated rows.
    fn candidates(&self) -> Candidates;

    /// Whether the derived candidates only apply to a node in the assertion's context (product).
    /// An equal RPM stream (e.g. `el9_0` and `el9_0`) counts as being in the product.
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
    let fixed_is_first_fixed =
        Enabled::load(CorrelationOptionKey::FixedIsFirstFixed, connection).await?;

    Ok(vec![
        Box::new(suse::SuseRecommendedBefore),
        Box::new(suse::SuseRecommended),
        Box::new(any_version::AnyVersion::load(connection).await?),
        Box::new(csaf::FirstFixed(csaf::Source::Stated)),
        Box::new(csaf::FirstFixedBefore(csaf::Source::Stated)),
        Box::new(csaf::FirstFixed(csaf::Source::Fixed(
            fixed_is_first_fixed.clone(),
        ))),
        Box::new(csaf::FirstFixedBefore(csaf::Source::Fixed(
            fixed_is_first_fixed,
        ))),
        Box::new(csaf::FirstAffected),
        Box::new(csaf::LastAffected),
        Box::new(vls::SchemelessRange::Vls),
        Box::new(vls::SchemelessRange::Custom),
    ])
}

/// The publishers enabling a boolean correlation option.
#[derive(Clone)]
pub struct Enabled {
    /// The enabled options, one per publisher namespace.
    options: Vec<correlation_option::Model>,
}

impl Enabled {
    /// Load the publishers enabling the option.
    pub async fn load<C: ConnectionTrait>(
        key: CorrelationOptionKey,
        connection: &C,
    ) -> Result<Self, Error> {
        let options = correlation_option::Entity::find()
            .filter(correlation_option::Column::Key.eq(key))
            .all(connection)
            .await?
            .into_iter()
            .filter(|option| option.value == Value::Bool(true))
            .collect();
        Ok(Self { options })
    }

    /// The namespaces of the publishers enabling the option.
    fn namespaces(&self) -> Vec<&str> {
        self.options
            .iter()
            .map(|option| option.publisher_namespace.as_str())
            .collect()
    }

    /// The option of a publisher, if it enables it.
    fn enabled_by(&self, publisher_namespace: Option<&str>) -> Option<EnabledBy> {
        let publisher_namespace = publisher_namespace?.trim_end_matches('/');
        self.options
            .iter()
            .find(|option| option.publisher_namespace == publisher_namespace)
            .cloned()
            .map(EnabledBy::from)
    }
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

/// Stated rows with an exact version (e.g. `fixed` in `1.2-3`).
fn exact() -> SimpleExpr {
    Expr::expr(low())
        .is_not_null()
        .and(Expr::expr(low()).eq(Expr::col((
            version_range::Entity,
            version_range::Column::HighVersion,
        ))))
}

/// Stated rows of a publisher's advisories, with an exact version.
fn exact_of(namespaces: &[&str]) -> SimpleExpr {
    exact().and(published_by(namespaces))
}

/// Stated rows of the given status (slug), with an exact version.
fn exact_status(slug: &str) -> SimpleExpr {
    Expr::col((status::Entity, status::Column::Slug))
        .eq(slug)
        .and(exact())
}

/// Lower bound of the stated range.
fn low() -> SimpleExpr {
    Expr::col((version_range::Entity, version_range::Column::LowVersion))
}
