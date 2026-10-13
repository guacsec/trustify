//! A summary of a CSAF document.

use super::{Doc, none, status::StatusCategory};
use crate::advisory::{card_grid, field_card};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct OverviewProps {
    pub doc: Doc,
}

#[function_component(Overview)]
pub fn overview(props: &OverviewProps) -> Html {
    let csaf = &props.doc.csaf;
    let document = &csaf.document;
    let tracking = &document.tracking;
    let tree = csaf.product_tree.as_ref();

    let status_counts = StatusCategory::ALL
        .into_iter()
        .map(|category| {
            let count = csaf
                .vulnerabilities
                .iter()
                .filter_map(|vuln| vuln.product_status.as_ref())
                .map(|status| category.products(status).len())
                .sum::<usize>();
            (category, count)
        })
        .filter(|(_, count)| *count > 0)
        .collect::<Vec<_>>();

    let counts = [
        ("Products", props.doc.index.products().len()),
        (
            "Relationships",
            tree.map(|tree| tree.relationships.len())
                .unwrap_or_default(),
        ),
        (
            "Product groups",
            tree.map(|tree| tree.product_groups.len())
                .unwrap_or_default(),
        ),
        ("Vulnerabilities", csaf.vulnerabilities.len()),
    ];

    let mut cards = vec![
        field_card(
            "Document",
            html! {
                <>
                    <DescriptionGroup term="Category">{ document.category.to_string() }</DescriptionGroup>
                    <DescriptionGroup term="CSAF version">{ document.csaf_version.to_string() }</DescriptionGroup>
                    <DescriptionGroup term="Aggregate severity">
                        { document.aggregate_severity.as_ref().map(|severity| html!(severity.text.to_string())).unwrap_or_else(none) }
                    </DescriptionGroup>
                    <DescriptionGroup term="TLP">
                        {
                            document.distribution.as_ref()
                                .and_then(|distribution| distribution.tlp.as_ref())
                                .map(|tlp| html!(tlp.label.to_string()))
                                .unwrap_or_else(none)
                        }
                    </DescriptionGroup>
                    <DescriptionGroup term="Language">
                        { document.lang.as_ref().map(|lang| html!(lang.to_string())).unwrap_or_else(none) }
                    </DescriptionGroup>
                </>
            },
        ),
        field_card(
            "Tracking",
            html! {
                <>
                    <DescriptionGroup term="ID">{ tracking.id.to_string() }</DescriptionGroup>
                    <DescriptionGroup term="Status">{ tracking.status.to_string() }</DescriptionGroup>
                    <DescriptionGroup term="Version">{ tracking.version.to_string() }</DescriptionGroup>
                    <DescriptionGroup term="Revisions">{ tracking.revision_history.len().to_string() }</DescriptionGroup>
                    <DescriptionGroup term="Initial release">{ &tracking.initial_release_date }</DescriptionGroup>
                    <DescriptionGroup term="Current release">{ &tracking.current_release_date }</DescriptionGroup>
                </>
            },
        ),
        field_card(
            "Publisher",
            html! {
                <>
                    <DescriptionGroup term="Name">{ document.publisher.name.to_string() }</DescriptionGroup>
                    <DescriptionGroup term="Category">{ document.publisher.category.to_string() }</DescriptionGroup>
                    <DescriptionGroup term="Namespace">{ &document.publisher.namespace }</DescriptionGroup>
                </>
            },
        ),
        field_card(
            "Contents",
            html! {
                { for counts.into_iter().map(|(title, count)| html! {
                    <DescriptionGroup term={title}>{ count.to_string() }</DescriptionGroup>
                }) }
            },
        ),
    ];
    if !status_counts.is_empty() {
        cards.push(field_card(
            "Product status",
            html! {
                { for status_counts.into_iter().map(|(category, count)| html! {
                    <DescriptionGroup term={category.title()}>{ category.label(count) }</DescriptionGroup>
                }) }
            },
        ));
    }

    html! {
        <Stack gutter=true>
            <StackItem>
                <Title level={Level::H2}>{ document.title.to_string() }</Title>
            </StackItem>
            <StackItem>
                { card_grid(cards) }
            </StackItem>
        </Stack>
    }
}
