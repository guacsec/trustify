//! Versionless PURLs: a status of all versions, for publishers enabling it by option.
//!
//! Some publishers state the status of a package in a product for all versions, using a PURL
//! without a version (e.g. Red Hat `pkg:rpm/redhat/golang?arch=src`, SUSE
//! `pkg:rpm/suse/openssl-3@`). That is stored as stated, as the exact, empty version, which never
//! matches. For publishers with the option `versionless_purl` enabled, this rule reads such a
//! statement as unbounded, and records the option with the evidence.
//!
//! Such a statement identifies the package only through its product, so it requires the node to
//! be in the statement's context (product).

use super::{RangeRule, low, published_by};
use crate::{
    error::Error,
    extractor::purl::{Candidates, stated_scheme},
    model::EnabledBy,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    sea_query::{Expr, SimpleExpr},
};
use serde_json::Value;
use trustify_entity::{
    correlation_option::{self, CorrelationOptionKey},
    status, version_range,
};

/// Reads versionless PURLs as all versions, for the publishers enabling it.
pub struct AnyVersion {
    /// The enabled options, one per publisher namespace.
    options: Vec<correlation_option::Model>,
}

impl AnyVersion {
    /// Load the publishers which enable the option.
    pub async fn load<C: ConnectionTrait>(connection: &C) -> Result<Self, Error> {
        let options = correlation_option::Entity::find()
            .filter(correlation_option::Column::Key.eq(CorrelationOptionKey::VersionlessPurl))
            .all(connection)
            .await?
            .into_iter()
            .filter(|option| option.value == Value::Bool(true))
            .collect();
        Ok(Self { options })
    }
}

impl RangeRule for AnyVersion {
    fn id(&self) -> &'static str {
        "purl_any_version"
    }

    /// Lower, as the statement is about a product, which isn't considered yet.
    fn confidence(&self) -> f64 {
        0.7
    }

    fn candidates(&self) -> Candidates {
        let namespaces = self
            .options
            .iter()
            .map(|option| option.publisher_namespace.as_str())
            .collect::<Vec<_>>();
        let high = Expr::col((version_range::Entity, version_range::Column::HighVersion));
        let unbounded = || -> SimpleExpr { Expr::cust("NULL") };

        Candidates {
            // the exact, empty version, by an enabled publisher
            condition: Expr::expr(low())
                .eq("")
                .and(high.eq(""))
                .and(published_by(&namespaces)),
            status: Expr::col((status::Entity, status::Column::Slug)).into(),
            scheme: stated_scheme(),
            // (unbounded, unbounded)
            low_version: unbounded(),
            low_inclusive: Expr::val(false).into(),
            high_version: unbounded(),
            high_inclusive: Expr::val(false).into(),
        }
    }

    /// A versionless statement identifies the package only through its product.
    fn requires_context(&self) -> bool {
        true
    }

    fn enabled_by(&self, publisher_namespace: Option<&str>) -> Option<EnabledBy> {
        let publisher_namespace = publisher_namespace?.trim_end_matches('/');
        self.options
            .iter()
            .find(|option| option.publisher_namespace == publisher_namespace)
            .cloned()
            .map(EnabledBy::from)
    }
}
