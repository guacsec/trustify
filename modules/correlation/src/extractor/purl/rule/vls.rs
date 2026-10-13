//! CSAF vers-like specifiers (vls): a range stated without a versioning scheme.
//!
//! A CSAF `product_version_range` may hold a vls (e.g. `<4.2`) instead of a `vers:` URI. It only
//! states the constraints, not how to compare versions, and is stored with the version scheme
//! `vls`, which `version_matches()` doesn't know. The CSAF standard leaves evaluating it to tools,
//! "on best effort basis".
//!
//! This rule evaluates such a range with the versioning scheme of the matched PURL's type (e.g.
//! semver for `pkg:npm/…`). PURL types without a known scheme don't match. As the scheme is
//! inferred, its confidence is lower than the one of a stated range.
//!
//! The same applies to a CVE range of the version type `custom` (stored with the version scheme
//! `custom`), whose versioning scheme is unspecified.

use super::RangeRule;
use crate::extractor::purl::{Candidates, stated_scheme};
use sea_orm::sea_query::{CaseStatement, Expr, ExprTrait, SimpleExpr};
use trustify_entity::{base_purl, status, version_range, version_scheme::VersionScheme};

/// The versioning scheme of PURL types, see
/// <https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst>.
const PURL_TYPE_SCHEMES: &[(&str, VersionScheme)] = &[
    ("cargo", VersionScheme::Cargo),
    ("composer", VersionScheme::Packagist),
    ("gem", VersionScheme::Gem),
    ("golang", VersionScheme::Golang),
    ("hex", VersionScheme::Hex),
    ("maven", VersionScheme::Maven),
    ("npm", VersionScheme::Npm),
    ("nuget", VersionScheme::NuGet),
    ("pub", VersionScheme::Pub),
    ("pypi", VersionScheme::Python),
    ("rpm", VersionScheme::Rpm),
    ("swift", VersionScheme::Swift),
];

/// Evaluates ranges without a versioning scheme with the one of the PURL type.
pub enum SchemelessRange {
    /// A CSAF vls range.
    Vls,
    /// A CVE range of the version type `custom`.
    Custom,
}

impl SchemelessRange {
    /// The version scheme the range is stored with.
    fn stored(&self) -> VersionScheme {
        match self {
            Self::Vls => VersionScheme::Vls,
            Self::Custom => VersionScheme::Custom,
        }
    }
}

impl RangeRule for SchemelessRange {
    fn id(&self) -> &'static str {
        match self {
            Self::Vls => "purl_vls_range",
            Self::Custom => "purl_custom_range",
        }
    }

    /// Lower, as the versioning scheme is inferred from the PURL type.
    fn confidence(&self) -> f64 {
        0.6
    }

    fn candidates(&self) -> Candidates {
        let scheme = PURL_TYPE_SCHEMES
            .iter()
            .fold(CaseStatement::new(), |case, (ty, scheme)| {
                case.case(
                    Expr::col((base_purl::Entity, base_purl::Column::Type)).eq(*ty),
                    Expr::val(scheme.to_string()),
                )
            })
            .finally(Expr::cust("NULL"));

        let range = |column| Expr::col((version_range::Entity, column));
        Candidates {
            condition: Expr::expr(stated_scheme()).eq(self.stored().to_string()),
            status: Expr::col((status::Entity, status::Column::Slug)),
            scheme: SimpleExpr::Case(Box::new(scheme)),
            low_version: range(version_range::Column::LowVersion),
            low_inclusive: range(version_range::Column::LowInclusive),
            high_version: range(version_range::Column::HighVersion),
            high_inclusive: range(version_range::Column::HighInclusive),
        }
    }
}
