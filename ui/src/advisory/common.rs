//! The information about an advisory stored in the database, the same for all formats.

use super::{card_grid, field_card, statements::VulnerabilityStatements};
use crate::sort::{missing_last, ordered, text, use_sort};
use patternfly_yew::prelude::*;
use std::{cmp::Ordering, rc::Rc};
use trustify_client::api::types::{AdvisoryDetails, AdvisoryVulnerabilitySummary, Severity};
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct CommonTabProps {
    /// The ID of the advisory, without the `urn:uuid:` prefix.
    pub advisory_id: AttrValue,
    pub details: Rc<AdvisoryDetails>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum VulnColumn {
    Identifier,
    Title,
    Severity,
    Score,
}

#[derive(Clone, PartialEq)]
struct VulnEntry {
    advisory_id: AttrValue,
    vulnerability: AdvisoryVulnerabilitySummary,
}

impl TableEntryRenderer<VulnColumn> for VulnEntry {
    fn render_cell(&self, context: CellContext<'_, VulnColumn>) -> Cell {
        let vulnerability = &self.vulnerability;
        match context.column {
            VulnColumn::Identifier => html!(<strong>{ &vulnerability.identifier }</strong>).into(),
            VulnColumn::Title => html!(vulnerability.title.as_deref().unwrap_or("\u{2014}")).into(),
            VulnColumn::Severity => {
                if let Some(bs) = &vulnerability.base_score {
                    html!(severity_label(&bs.severity)).into()
                } else {
                    html!(<i>{ "\u{2014}" }</i>).into()
                }
            }
            VulnColumn::Score => {
                if let Some(bs) = &vulnerability.base_score {
                    html!(format!("{:.1}", bs.score)).into()
                } else {
                    html!(<i>{ "\u{2014}" }</i>).into()
                }
            }
        }
    }

    /// What the advisory states for the vulnerability, as stored in the database.
    fn render_details(&self) -> Vec<Span> {
        vec![Span::max(html! {
            <VulnerabilityStatements
                advisory_id={self.advisory_id.clone()}
                vulnerability={self.vulnerability.identifier.clone()}
            />
        })]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

/// Compare two vulnerabilities by a column, ascending. Severity and score both sort by the
/// score, vulnerabilities without one last.
fn compare(
    column: VulnColumn,
    a: &AdvisoryVulnerabilitySummary,
    b: &AdvisoryVulnerabilitySummary,
) -> Ordering {
    let score = |v: &AdvisoryVulnerabilitySummary| v.base_score.as_ref().map(|s| s.score);
    match column {
        VulnColumn::Identifier => text(&a.identifier, &b.identifier),
        VulnColumn::Title => missing_last(a.title.as_deref(), b.title.as_deref()),
        VulnColumn::Severity | VulnColumn::Score => match (score(a), score(b)) {
            (Some(a), Some(b)) => a.total_cmp(&b),
            (a, b) => missing_last(a.map(|_| ()), b.map(|_| ())),
        },
    }
    .then_with(|| text(&a.identifier, &b.identifier))
}

#[function_component(CommonTab)]
pub fn common_tab(props: &CommonTabProps) -> Html {
    let details = &props.details;
    let sort = use_sort::<VulnColumn>(None);

    let entries = use_memo(
        (props.advisory_id.clone(), details.clone(), sort.sortby),
        |(advisory_id, details, sortby)| {
            let mut vulnerabilities = details.vulnerabilities.iter().collect::<Vec<_>>();
            if let Some(sortby) = sortby {
                vulnerabilities.sort_by(|a, b| ordered(sortby.order, compare(sortby.index, a, b)));
            }
            vulnerabilities
                .into_iter()
                .map(|vulnerability| VulnEntry {
                    advisory_id: advisory_id.clone(),
                    vulnerability: vulnerability.clone(),
                })
                .collect::<Vec<_>>()
        },
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<VulnColumn>>
            <TableColumn<VulnColumn> label="Vulnerability" index={VulnColumn::Identifier} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<VulnColumn> label="Title" index={VulnColumn::Title} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<VulnColumn> label="Severity" index={VulnColumn::Severity} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<VulnColumn> label="Score" index={VulnColumn::Score} sortby={sort.sortby} onsort={sort.onsort.clone()} />
        </TableHeader<VulnColumn>>
    };

    let mut labels = details.labels.0.iter().collect::<Vec<_>>();
    labels.sort();

    html! {
        <>
            { card_grid([
                field_card("Advisory", html! {
                    <>
                        <DescriptionGroup term="Identifier">{ &details.identifier }</DescriptionGroup>
                        <DescriptionGroup term="Document ID">{ &details.document_id }</DescriptionGroup>
                        <DescriptionGroup term="Issuer">
                            { details.issuer.as_ref().map(|issuer| issuer.name.clone()).unwrap_or_else(|| "\u{2014}".into()) }
                        </DescriptionGroup>
                        <DescriptionGroup term="Published">{ optional(details.published) }</DescriptionGroup>
                        <DescriptionGroup term="Modified">{ optional(details.modified) }</DescriptionGroup>
                        if let Some(withdrawn) = &details.withdrawn {
                            <DescriptionGroup term="Withdrawn">{ withdrawn.to_string() }</DescriptionGroup>
                        }
                    </>
                }),
                field_card("Source document", html! {
                    <>
                        <DescriptionGroup term="Ingested">{ details.ingested.to_string() }</DescriptionGroup>
                        <DescriptionGroup term="Size">{ format!("{} bytes", details.size) }</DescriptionGroup>
                        <DescriptionGroup term="SHA-256"><code class="trustify-break-all">{ &details.sha256 }</code></DescriptionGroup>
                    </>
                }),
                field_card("Labels", html! {
                    { for labels.into_iter().map(|(key, value)| html! {
                        <DescriptionGroup term={key.clone()}>{ value }</DescriptionGroup>
                    }) }
                }),
            ]) }

            <br />

            if !details.vulnerabilities.is_empty() {
                <Title level={Level::H2}>
                    { "Vulnerabilities " }
                    <Badge>{ details.vulnerabilities.len().to_string() }</Badge>
                </Title>
                <Table<VulnColumn, UseTableData<VulnColumn, MemoizedTableModel<VulnEntry>>>
                    mode={TableMode::CompactExpandable}
                    {header}
                    {entries}
                    {onexpand}
                />
            } else {
                <EmptyState
                    title="No vulnerabilities"
                    icon={Icon::CheckCircle}
                    size={Size::XXXXLarge}
                >
                    { "This advisory does not reference any vulnerabilities." }
                </EmptyState>
            }
        </>
    }
}

fn optional(value: Option<impl ToString>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "\u{2014}".into())
}

fn severity_label(severity: &Severity) -> Html {
    let (label, color) = match severity {
        Severity::Critical => ("Critical", Color::Red),
        Severity::High => ("High", Color::Orange),
        Severity::Medium => ("Medium", Color::Yellow),
        Severity::Low => ("Low", Color::Blue),
        Severity::None => ("None", Color::Grey),
    };
    html! { <Label label={label} {color} /> }
}
