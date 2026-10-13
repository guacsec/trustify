//! A summary of an OSV record.

use super::{Doc, id_list, json_section, none, stated};
use crate::advisory::{card_grid, field_card};
use ::osv::schema::{Severity, SeverityType};
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use patternfly_yew::prelude::*;
use std::str::FromStr;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct OverviewProps {
    pub doc: Doc,
}

/// The base score of a CVSS severity, `None` for other types, or if it can't be calculated.
fn cvss_score(severity: &Severity) -> Option<f64> {
    let vector = severity.score.as_str();
    match severity.severity_type {
        SeverityType::CVSSv2 => CvssV2::from_str(vector).ok()?.calculated_base_score(),
        SeverityType::CVSSv3 => CvssV3::from_str(vector).ok()?.calculated_base_score(),
        SeverityType::CVSSv4 => CvssV4::from_str(vector).ok()?.calculated_base_score(),
        _ => None,
    }
}

fn severity(severity: &Severity) -> Html {
    html! {
        <DescriptionGroup term={stated(&severity.severity_type)}>
            if let Some(score) = cvss_score(severity) {
                <strong>{ format!("{score:.1}") }</strong>
                <br />
            }
            <small><code>{ &severity.score }</code></small>
        </DescriptionGroup>
    }
}

#[function_component(Overview)]
pub fn overview(props: &OverviewProps) -> Html {
    let osv = &*props.doc;
    let affected = osv.affected.as_deref().unwrap_or_default();
    let severities = osv.severity.as_deref().unwrap_or_default();
    let credits = osv.credits.as_deref().unwrap_or_default();

    let counts = [
        ("Affected packages", affected.len()),
        (
            "Ranges",
            affected
                .iter()
                .map(|a| a.ranges.as_ref().map(Vec::len).unwrap_or_default())
                .sum(),
        ),
        (
            "Listed versions",
            affected
                .iter()
                .map(|a| a.versions.as_ref().map(Vec::len).unwrap_or_default())
                .sum(),
        ),
        (
            "References",
            osv.references.as_ref().map(Vec::len).unwrap_or_default(),
        ),
    ];

    let mut cards = vec![
        field_card(
            "Record",
            html! {
                <>
                    <DescriptionGroup term="ID">{ &osv.id }</DescriptionGroup>
                    <DescriptionGroup term="Schema version">
                        { osv.schema_version.as_ref().map(|v| html!(v)).unwrap_or_else(none) }
                    </DescriptionGroup>
                    <DescriptionGroup term="Published">
                        { osv.published.map(|v| html!(v.to_string())).unwrap_or_else(none) }
                    </DescriptionGroup>
                    <DescriptionGroup term="Modified">{ osv.modified.to_string() }</DescriptionGroup>
                    <DescriptionGroup term="Withdrawn">
                        { osv.withdrawn.map(|v| html!(v.to_string())).unwrap_or_else(none) }
                    </DescriptionGroup>
                </>
            },
        ),
        field_card(
            "Identifiers",
            html! {
                <>
                    <DescriptionGroup term="Aliases">{ id_list(osv.aliases.as_ref()) }</DescriptionGroup>
                    <DescriptionGroup term="Upstream">{ id_list(osv.upstream.as_ref()) }</DescriptionGroup>
                    <DescriptionGroup term="Related">{ id_list(osv.related.as_ref()) }</DescriptionGroup>
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
    if !severities.is_empty() {
        cards.push(field_card(
            "Severity",
            html!({ for severities.iter().map(severity) }),
        ));
    }
    if !credits.is_empty() {
        cards.push(field_card(
            "Credits",
            html! {
                { for credits.iter().map(|credit| html! {
                    <DescriptionGroup term={credit.credit_type.as_ref().map(stated).unwrap_or_else(|| "Credit".to_string())}>
                        { &credit.name }
                    </DescriptionGroup>
                }) }
            },
        ));
    }

    html! {
        <Stack gutter=true>
            if let Some(summary) = &osv.summary {
                <StackItem>
                    <Title level={Level::H2}>{ summary }</Title>
                </StackItem>
            }
            <StackItem>
                { card_grid(cards) }
            </StackItem>
            if let Some(details) = &osv.details {
                <StackItem>
                    <Card size={CardSize::Compact}>
                        <CardTitle>{ "Details" }</CardTitle>
                        <CardBody>
                            <p class="trustify-pre-wrap">{ details }</p>
                        </CardBody>
                    </Card>
                </StackItem>
            }
            <StackItem>
                { json_section("Database specific", osv.database_specific.as_ref()) }
            </StackItem>
        </Stack>
    }
}
