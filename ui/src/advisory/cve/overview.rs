//! A summary of a CVE record.

use super::{Doc, english, none, provider_label, timestamp};
use crate::{
    advisory::{card_grid, field_card},
    score::{ScoreLabel, rating},
};
use ::cve::{Cve, common::Description, published::Metric};
use patternfly_yew::prelude::*;
use serde_json::Value;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct OverviewProps {
    pub doc: Doc,
}

/// The CVSS scores of a metric: version, base score, and vector.
/// The CVSS metrics: the version, whether it is CVSS 2.0, the base score and the vector.
fn cvss(metric: &Metric) -> Vec<(&'static str, bool, Option<f64>, Option<&str>)> {
    [
        ("CVSS 4.0", false, &metric.cvss_v4_0),
        ("CVSS 3.1", false, &metric.cvss_v3_1),
        ("CVSS 3.0", false, &metric.cvss_v3_0),
        ("CVSS 2.0", true, &metric.cvss_v2_0),
    ]
    .into_iter()
    .filter_map(|(version, v2, value)| {
        let value = value.as_ref()?;
        Some((
            version,
            v2,
            value.get("baseScore").and_then(Value::as_f64),
            value.get("vectorString").and_then(Value::as_str),
        ))
    })
    .collect()
}

/// Prose of a record (e.g. workarounds), in English, collapsed.
fn prose(title: &'static str, descriptions: &[Description]) -> Html {
    let Some(description) = english(descriptions) else {
        return html!();
    };
    html! {
        <ExpandableSection toggle_text_hidden={title} toggle_text_expanded={title}>
            <p class="trustify-pre-wrap">{ &description.value }</p>
        </ExpandableSection>
    }
}

#[function_component(Overview)]
pub fn overview(props: &OverviewProps) -> Html {
    let doc = &props.doc;
    let containers = doc.containers();

    let (metadata, state, rejected) = match &doc.cve {
        Cve::Published(published) => (&published.metadata.common, "PUBLISHED", None),
        Cve::Rejected(rejected) => (
            &rejected.metadata.common,
            "REJECTED",
            Some(rejected.metadata.date_rejected),
        ),
    };

    let mut cards = vec![
        field_card(
            "Record",
            html! {
                <>
                    <DescriptionGroup term="ID">{ &metadata.id }</DescriptionGroup>
                    <DescriptionGroup term="State">{ state }</DescriptionGroup>
                    <DescriptionGroup term="Assigner">
                        { metadata.assigner_short_name.as_ref().map(|v| html!(v)).unwrap_or_else(none) }
                    </DescriptionGroup>
                    <DescriptionGroup term="Reserved">{ timestamp(metadata.date_reserved) }</DescriptionGroup>
                    <DescriptionGroup term="Published">{ timestamp(metadata.date_published) }</DescriptionGroup>
                    <DescriptionGroup term="Updated">{ timestamp(metadata.date_updated) }</DescriptionGroup>
                    if let Some(rejected) = rejected {
                        <DescriptionGroup term="Rejected">{ timestamp(rejected) }</DescriptionGroup>
                    }
                </>
            },
        ),
        field_card(
            "Containers",
            html! {
                { for containers.iter().map(|container| html! {
                    <DescriptionGroup term={container.provider.clone()}>
                        { provider_label(container) }
                        { format!(
                            " {} affected, {} CPE applicability, {} references",
                            container.affected.len(),
                            container.applicability.len(),
                            container.references.len(),
                        ) }
                    </DescriptionGroup>
                }) }
            },
        ),
    ];

    let scores = doc
        .metrics()
        .into_iter()
        .flat_map(|(provider, metric)| {
            cvss(metric)
                .into_iter()
                .map(move |(version, v2, score, vector)| {
                    (provider.clone(), version, v2, score, vector)
                })
        })
        .collect::<Vec<_>>();
    if !scores.is_empty() {
        cards.push(field_card(
            "Severity",
            html! {
                { for scores.into_iter().map(|(provider, version, v2, score, vector)| html! {
                    <DescriptionGroup term={format!("{version} ({provider})")}>
                        if let Some(score) = score {
                            <ScoreLabel {score} severity={rating(score, v2)} />
                            <br />
                        }
                        <small><crate::tools::InlineCvss value={vector.unwrap_or_default().to_string()} /></small>
                    </DescriptionGroup>
                }) }
            },
        ));
    }

    let Cve::Published(published) = &doc.cve else {
        let Cve::Rejected(rejected) = &doc.cve else {
            return html!();
        };
        return html! {
            <Stack gutter=true>
                <StackItem>{ card_grid(cards) }</StackItem>
                <StackItem>
                    <Alert title="Rejected" r#type={AlertType::Warning} inline=true>
                        if let Some(reason) = english(&rejected.containers.cna.rejected_reasons) {
                            <p class="trustify-pre-wrap">{ &reason.value }</p>
                        }
                        if !rejected.containers.cna.replaced_by.is_empty() {
                            <p>{ "Replaced by: " }{ rejected.containers.cna.replaced_by.join(", ") }</p>
                        }
                    </Alert>
                </StackItem>
            </Stack>
        };
    };
    let cna = &published.containers.cna;

    let cwes = cna
        .problem_types
        .iter()
        .flat_map(|problem_type| &problem_type.descriptions)
        .collect::<Vec<_>>();
    if !cwes.is_empty() {
        cards.push(field_card(
            "Problem types",
            html! {
                { for cwes.into_iter().map(|cwe| html! {
                    <DescriptionGroup term={cwe.cwe_id.clone().unwrap_or_else(|| "Problem".to_string())}>
                        { &cwe.description }
                    </DescriptionGroup>
                }) }
            },
        ));
    }

    let capecs = cna
        .impacts
        .iter()
        .filter_map(|impact| Some((impact.capec_id.as_deref()?, english(&impact.descriptions)?)))
        .collect::<Vec<_>>();
    if !capecs.is_empty() {
        cards.push(field_card(
            "Impacts",
            html! {
                { for capecs.into_iter().map(|(capec, description)| html! {
                    <DescriptionGroup term={capec.to_string()}>{ &description.value }</DescriptionGroup>
                }) }
            },
        ));
    }

    html! {
        <Stack gutter=true>
            if let Some(title) = &cna.title {
                <StackItem>
                    <Title level={Level::H2}>{ title }</Title>
                </StackItem>
            }
            <StackItem>
                { card_grid(cards) }
            </StackItem>
            if let Some(description) = english(&cna.descriptions) {
                <StackItem>
                    <Card size={CardSize::Compact}>
                        <CardTitle>{ "Description" }</CardTitle>
                        <CardBody>
                            <p class="trustify-pre-wrap">{ &description.value }</p>
                        </CardBody>
                    </Card>
                </StackItem>
            }
            <StackItem>{ prose("Workarounds", &cna.workarounds) }</StackItem>
            <StackItem>{ prose("Solutions", &cna.solutions) }</StackItem>
            <StackItem>{ prose("Exploits", &cna.exploits) }</StackItem>
            <StackItem>{ prose("Configurations", &cna.configurations) }</StackItem>
            if !cna.credits.is_empty() {
                <StackItem>
                    <ExpandableSection toggle_text_hidden="Credits" toggle_text_expanded="Credits">
                        <List>
                            { for cna.credits.iter().map(|credit| html_nested!(<ListItem>{ &credit.value }</ListItem>)) }
                        </List>
                    </ExpandableSection>
                </StackItem>
            }
            if !cna.timeline.is_empty() {
                <StackItem>
                    <ExpandableSection toggle_text_hidden="Timeline" toggle_text_expanded="Timeline">
                        <List>
                            { for cna.timeline.iter().map(|entry| html_nested! {
                                <ListItem>{ format!("{}: {}", entry.time.assume_utc(), entry.value) }</ListItem>
                            }) }
                        </List>
                    </ExpandableSection>
                </StackItem>
            }
        </Stack>
    }
}

#[cfg(test)]
mod test {
    use super::{super::parse, cvss};

    const KERNEL: &str = include_str!(
        "../../../../etc/test-data/scenarios/S26_cve_cpe_applicability_kernel/cve/CVE-2024-26581.json"
    );

    /// The scores of the CNA and of an ADP (CVE-2024-26581).
    #[test]
    fn scores_of_containers() {
        let doc = parse(KERNEL).expect("record parses");
        const VECTOR: &str = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
        assert_eq!(
            doc.metrics()
                .into_iter()
                .flat_map(|(provider, metric)| cvss(metric)
                    .into_iter()
                    .map(move |score| (provider.clone(), score)))
                .collect::<Vec<_>>(),
            [
                (
                    "Linux".to_string(),
                    ("CVSS 3.1", false, Some(7.8), Some(VECTOR))
                ),
                (
                    "CISA-ADP".to_string(),
                    ("CVSS 3.1", false, Some(7.8), Some(VECTOR))
                ),
            ]
        );
    }
}
