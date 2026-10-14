//! The product status categories of a CSAF vulnerability.

use super::{Doc, none};
use ::csaf::schema::csaf2_0::schema::{ProductIdT, ProductStatus, ProductsT};
use patternfly_yew::prelude::*;
use std::collections::HashMap;
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

/// For each product, how many vulnerabilities state each status category for it, in the order
/// of [`StatusCategory::ALL`]. Products without any status are left out.
pub type StatusCounts = HashMap<String, [usize; StatusCategory::ALL.len()]>;

/// Count the status categories of each product, over all vulnerabilities.
pub fn status_counts(doc: &Doc) -> StatusCounts {
    let mut result = StatusCounts::new();
    for status in doc
        .csaf
        .vulnerabilities
        .iter()
        .filter_map(|vuln| vuln.product_status.as_ref())
    {
        for (n, category) in StatusCategory::ALL.into_iter().enumerate() {
            for id in category.products(status) {
                result.entry(id.to_string()).or_default()[n] += 1;
            }
        }
    }
    result
}

/// Labels for the status categories of a product, with a count when several vulnerabilities
/// state the same one.
pub fn status_labels(counts: Option<&[usize; StatusCategory::ALL.len()]>) -> Html {
    let Some(counts) = counts else {
        return none();
    };
    html! {
        <Flex space_items={[SpaceItems::Small]}>
            { for StatusCategory::ALL.into_iter().zip(counts).filter(|(_, count)| **count > 0).map(|(category, count)| {
                let label = match count {
                    1 => category.title().to_string(),
                    count => format!("{} ({count})", category.title()),
                };
                html_nested! {
                    <FlexItem>
                        <Label {label} color={category.color()} compact=true />
                    </FlexItem>
                }
            }) }
        </Flex>
    }
}
