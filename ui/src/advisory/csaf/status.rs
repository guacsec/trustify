//! The product status categories of a CSAF vulnerability.

use ::csaf::schema::csaf2_0::schema::{ProductIdT, ProductStatus, ProductsT};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusCategory {
    KnownAffected,
    FirstAffected,
    LastAffected,
    UnderInvestigation,
    KnownNotAffected,
    FirstFixed,
    Fixed,
    Recommended,
}

impl StatusCategory {
    pub const ALL: [Self; 8] = [
        Self::KnownAffected,
        Self::FirstAffected,
        Self::LastAffected,
        Self::UnderInvestigation,
        Self::KnownNotAffected,
        Self::FirstFixed,
        Self::Fixed,
        Self::Recommended,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::KnownAffected => "Known affected",
            Self::FirstAffected => "First affected",
            Self::LastAffected => "Last affected",
            Self::UnderInvestigation => "Under investigation",
            Self::KnownNotAffected => "Known not affected",
            Self::FirstFixed => "First fixed",
            Self::Fixed => "Fixed",
            Self::Recommended => "Recommended",
        }
    }

    pub fn color(self) -> Color {
        match self {
            Self::KnownAffected | Self::FirstAffected | Self::LastAffected => Color::Red,
            Self::UnderInvestigation => Color::Orange,
            Self::KnownNotAffected => Color::Green,
            Self::FirstFixed | Self::Fixed => Color::Blue,
            Self::Recommended => Color::Purple,
        }
    }

    /// The product IDs of this category.
    pub fn products(self, status: &ProductStatus) -> &[ProductIdT] {
        let products = match self {
            Self::KnownAffected => &status.known_affected,
            Self::FirstAffected => &status.first_affected,
            Self::LastAffected => &status.last_affected,
            Self::UnderInvestigation => &status.under_investigation,
            Self::KnownNotAffected => &status.known_not_affected,
            Self::FirstFixed => &status.first_fixed,
            Self::Fixed => &status.fixed,
            Self::Recommended => &status.recommended,
        };
        products
            .as_ref()
            .map(|ProductsT(ids)| ids.as_slice())
            .unwrap_or_default()
    }

    /// A label for this category, with a count.
    pub fn label(self, count: usize) -> Html {
        html!(<Label label={format!("{}: {count}", self.title())} color={self.color()} compact=true />)
    }
}
