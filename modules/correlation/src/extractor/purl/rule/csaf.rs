//! CSAF: the meaning of the product statuses stating a single version as a version range.
//!
//! CSAF states `first_fixed`, `first_affected` and `last_affected` for a version, meaning a
//! boundary of the versions of a release which are fixed or affected. Ingestion stores them as
//! stated, as the exact version. These rules derive the range they mean. The stream scoping of
//! the PURL extractor ensures a version is only compared within its own stream.
//!
//! Some publishers state `fixed` with the meaning of `first_fixed`, e.g. Red Hat only states the
//! build fixing a vulnerability in a product stream. For publishers with the option
//! `fixed_is_first_fixed` enabled, the `first_fixed` rules read their `fixed` as `first_fixed`,
//! as evidence of their own type, which records the option. Reading such a `fixed` as fixed from
//! that version on requires the node to be in the statement's product, or in its RPM stream.

use super::{Enabled, RangeRule, exact_of, exact_status, low};
use crate::{
    extractor::purl::{Candidates, stated_scheme},
    model::{AssertionOrigin, EnabledBy},
};
use sea_orm::sea_query::{Expr, ExprTrait, SimpleExpr};
use trustify_entity::status;

/// The statements a `first_fixed` rule reads as `first_fixed`.
pub enum Source {
    /// Stated as `first_fixed`.
    Stated,
    /// Stated as `fixed` by a publisher enabling `fixed_is_first_fixed`.
    Fixed(Enabled),
}

impl Source {
    fn origin(&self) -> AssertionOrigin {
        match self {
            Self::Stated => AssertionOrigin::Stated,
            Self::Fixed(_) => AssertionOrigin::PublisherPolicy,
        }
    }

    /// The stated rows, with an exact version.
    fn condition(&self) -> SimpleExpr {
        match self {
            Self::Stated => exact_status("first_fixed"),
            Self::Fixed(enabled) => Expr::col((status::Entity, status::Column::Slug))
                .eq("fixed")
                .and(exact_of(&enabled.namespaces())),
        }
    }

    /// The evidence type: the stated one, or the one read by the option.
    fn id(&self, stated: &'static str, by_option: &'static str) -> &'static str {
        match self {
            Self::Stated => stated,
            Self::Fixed(_) => by_option,
        }
    }

    fn enabled_by(&self, publisher_namespace: Option<&str>) -> Option<EnabledBy> {
        match self {
            Self::Stated => None,
            Self::Fixed(enabled) => enabled.enabled_by(publisher_namespace),
        }
    }
}

/// Unbounded side of a range.
fn unbounded() -> SimpleExpr {
    Expr::cust("NULL")
}

/// From the stated version on: `[X, unbounded)`.
fn from(condition: SimpleExpr, status: &str) -> Candidates {
    Candidates {
        condition,
        status: Expr::val(status),
        scheme: stated_scheme(),
        low_version: low(),
        low_inclusive: Expr::val(true),
        high_version: unbounded(),
        high_inclusive: Expr::val(false),
    }
}

/// Up to the stated version: `(unbounded, X)`, or `(unbounded, X]` if inclusive.
fn up_to(condition: SimpleExpr, status: &str, inclusive: bool) -> Candidates {
    Candidates {
        condition,
        status: Expr::val(status),
        scheme: stated_scheme(),
        low_version: unbounded(),
        low_inclusive: Expr::val(false),
        high_version: low(),
        high_inclusive: Expr::val(inclusive),
    }
}

/// `first_fixed`: fixed from that version on.
pub struct FirstFixed(pub Source);

impl RangeRule for FirstFixed {
    fn origin(&self) -> AssertionOrigin {
        self.0.origin()
    }

    fn id(&self) -> &'static str {
        self.0.id("purl_first_fixed", "purl_fixed_as_first_fixed")
    }

    /// The stated meaning, or a publisher's convention.
    fn confidence(&self) -> f64 {
        match self.0 {
            Source::Stated => 1.0,
            Source::Fixed(_) => 0.9,
        }
    }

    fn candidates(&self) -> Candidates {
        from(self.0.condition(), "fixed")
    }

    /// A publisher's `fixed` is only known to be the first fix in its own product (stream), and a
    /// fix wins the verdict. Without the product or stream, a later version of another product,
    /// e.g. a version without a stream, would be fixed against the product's own statements.
    fn requires_context(&self) -> bool {
        matches!(self.0, Source::Fixed(_))
    }

    fn enabled_by(&self, publisher_namespace: Option<&str>) -> Option<EnabledBy> {
        self.0.enabled_by(publisher_namespace)
    }
}

/// `first_fixed`: the versions before aren't fixed, so they are affected.
pub struct FirstFixedBefore(pub Source);

impl RangeRule for FirstFixedBefore {
    fn origin(&self) -> AssertionOrigin {
        match self.0 {
            Source::Stated => AssertionOrigin::Inferred,
            Source::Fixed(_) => AssertionOrigin::PublisherPolicy,
        }
    }

    fn id(&self) -> &'static str {
        self.0.id(
            "purl_first_fixed_before",
            "purl_fixed_as_first_fixed_before",
        )
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        up_to(self.0.condition(), "affected", false)
    }

    /// A publisher's fix only implies affected versions within its product or RPM stream.
    fn requires_context(&self) -> bool {
        matches!(self.0, Source::Fixed(_))
    }

    fn enabled_by(&self, publisher_namespace: Option<&str>) -> Option<EnabledBy> {
        self.0.enabled_by(publisher_namespace)
    }
}

/// `first_affected`: affected from that version on (until a fix, which wins the verdict).
pub struct FirstAffected;

impl RangeRule for FirstAffected {
    fn origin(&self) -> AssertionOrigin {
        AssertionOrigin::Stated
    }
    fn id(&self) -> &'static str {
        "purl_first_affected"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        from(exact_status("first_affected"), "affected")
    }
}

/// `last_affected`: affected up to and including that version.
pub struct LastAffected;

impl RangeRule for LastAffected {
    fn origin(&self) -> AssertionOrigin {
        AssertionOrigin::Stated
    }
    fn id(&self) -> &'static str {
        "purl_last_affected"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn candidates(&self) -> Candidates {
        up_to(exact_status("last_affected"), "affected", true)
    }
}
