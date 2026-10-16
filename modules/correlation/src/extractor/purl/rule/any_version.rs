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
//!
//! This doesn't apply to OSV: its PURLs are versionless by the spec ("without the `@version`
//! component"), identifying the package, while the affected versions are stated by ranges and
//! lists. OSV ingestion never stores the empty version, and OSV advisories have no publisher
//! namespace to enable the option for.

use super::{Enabled, RangeRule, low, published_by};
use crate::{
    error::Error,
    extractor::purl::{Candidates, stated_scheme},
    model::{AssertionOrigin, EnabledBy},
};
use sea_orm::{
    ConnectionTrait,
    sea_query::{Expr, ExprTrait, SimpleExpr},
};
use trustify_entity::{correlation_option::CorrelationOptionKey, status, version_range};

/// Reads versionless PURLs as all versions, for the publishers enabling it.
pub struct AnyVersion(Enabled);

impl AnyVersion {
    /// Load the publishers which enable the option.
    pub async fn load<C: ConnectionTrait>(connection: &C) -> Result<Self, Error> {
        Ok(Self(
            Enabled::load(CorrelationOptionKey::VersionlessPurl, connection).await?,
        ))
    }
}

impl RangeRule for AnyVersion {
    fn origin(&self) -> AssertionOrigin {
        AssertionOrigin::PublisherPolicy
    }

    fn id(&self) -> &'static str {
        "purl_any_version"
    }

    /// Lower, as the statement is about a product, which isn't considered yet.
    fn confidence(&self) -> f64 {
        0.7
    }

    fn candidates(&self) -> Candidates {
        let namespaces = self.0.namespaces();
        let high = Expr::col((version_range::Entity, version_range::Column::HighVersion));
        let unbounded = || -> SimpleExpr { Expr::cust("NULL") };

        Candidates {
            // the exact, empty version, by an enabled publisher
            condition: Expr::expr(low())
                .eq("")
                .and(high.eq(""))
                .and(published_by(&namespaces)),
            status: Expr::col((status::Entity, status::Column::Slug)),
            scheme: stated_scheme(),
            // (unbounded, unbounded)
            low_version: unbounded(),
            low_inclusive: Expr::val(false),
            high_version: unbounded(),
            high_inclusive: Expr::val(false),
        }
    }

    /// A versionless statement identifies the package only through its product.
    fn requires_context(&self) -> bool {
        true
    }

    fn enabled_by(&self, publisher_namespace: Option<&str>) -> Option<EnabledBy> {
        self.0.enabled_by(publisher_namespace)
    }
}
