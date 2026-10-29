//! Paginated verdicts and their expandable evidence details.
use super::{
    CorrelationContentProps,
    common::{confidence_label, identifiers, matched_value, remediation, status_label, timestamp},
    pagination::{page_status, use_collection},
};
use crate::{
    advisory::advisory_link,
    model::{EvidenceDetail, EvidenceRemediation, ProviderMatch, VerdictSummary},
    resolution::{
        ResolutionAction, ResolutionButton, confidence_cell, product_names, provider_view,
    },
    score::primary_score,
};
use patternfly_yew::prelude::*;
use trustify_api::correlation::PreviewTarget;
use uuid::Uuid;
use yew::prelude::*;

/// Show one page of complete verdicts with expandable evidence details.
#[function_component(VerdictTable)]
pub(super) fn verdict_table(props: &CorrelationContentProps) -> Html {
    let (page, pagination, loading, error, freshness, onrefresh) =
        use_collection::<VerdictSummary>(props.sbom_id, "", false);
    let total = page.total.and_then(|n| usize::try_from(n).ok());
    let rows = use_memo((page.items.clone(), props.sbom_id), |(items, id)| {
        items
            .iter()
            .cloned()
            .map(|v| VerdictEntry(v, *id))
            .collect::<Vec<_>>()
    });
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(rows));
    let header = html_nested! {
        <TableHeader<VerdictColumn>>
            <TableColumn<VerdictColumn> label="Component" index={VerdictColumn::Component} />
            <TableColumn<VerdictColumn> label="Vulnerability" index={VerdictColumn::Vulnerability} />
            <TableColumn<VerdictColumn> label="Score" index={VerdictColumn::Score} />
            <TableColumn<VerdictColumn> label="Advisory" index={VerdictColumn::Advisory} />
            <TableColumn<VerdictColumn> label="Status" index={VerdictColumn::Status} />
            <TableColumn<VerdictColumn> label="Evidence" index={VerdictColumn::Evidence} />
        </TableHeader<VerdictColumn>>
    };
    html! {
        <>
            <super::processing::ProcessingStatus sbom_id={Some(props.sbom_id)} snapshot={freshness.clone()} {onrefresh} />
            <Title level={Level::H2}>{"Correlated components "}<Badge>{page.total.map(|n| n.to_string()).unwrap_or_default()}</Badge></Title>
            <SimplePagination {pagination} {total} />
            {page_status(&page, loading, error.as_deref(), if freshness.as_ref().is_none_or(|s| s.generation.is_none()) { "Verdicts not computed yet" } else { "No verdicts in completed results" })}
            if !loading && error.is_none() && !page.items.is_empty() {
                <Table<VerdictColumn, UseTableData<VerdictColumn, MemoizedTableModel<VerdictEntry>>>
                    mode={TableMode::Expandable} {header} {entries} {onexpand}
                />
            }
        </>
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum VerdictColumn {
    Component,
    Vulnerability,
    Score,
    Advisory,
    Status,
    Evidence,
}

#[derive(Clone, PartialEq)]
struct VerdictEntry(VerdictSummary, Uuid);

impl VerdictEntry {
    /// The remediations the advisories state for the evidence, each once per advisory.
    fn remediations(&self) -> Vec<(&EvidenceRemediation, &EvidenceDetail)> {
        let mut result = Vec::new();
        for evidence in &self.0.evidence {
            for remediation in &evidence.remediations {
                if !result
                    .iter()
                    .any(|(r, e): &(&EvidenceRemediation, &EvidenceDetail)| {
                        *r == remediation && e.advisory_id == evidence.advisory_id
                    })
                {
                    result.push((remediation, evidence));
                }
            }
        }
        result
    }
}

impl TableEntryRenderer<VerdictColumn> for VerdictEntry {
    fn render_cell(&self, context: CellContext<'_, VerdictColumn>) -> Cell {
        match context.column {
            VerdictColumn::Component => Cell::new(html! {
                <div>
                    { &self.0.component.name }
                    <div class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">
                        <code style="color: inherit;">{ &self.0.component.node_id }</code>
                    </div>
                </div>
            })
            .text_modifier(TextModifier::NoWrap),
            VerdictColumn::Vulnerability => html! {
                <>
                    <strong>{ &self.0.vulnerability.id }</strong>
                    if let Some(title) = &self.0.vulnerability.title {
                        <br />
                        <small>{ title }</small>
                    }
                    if !self.0.vulnerability.upstream.is_empty() {
                        <Tooltip text="The vulnerabilities this advisory refers to upstream. They are different vulnerabilities, not aliases.">
                            <div class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">
                                { "Upstream: " }{ self.0.vulnerability.upstream.join(", ") }
                            </div>
                        </Tooltip>
                    }
                </>
            }
            .into(),
            VerdictColumn::Score => primary_score(&self.0.vulnerability.scores).into(),
            VerdictColumn::Advisory => advisory_link(
                self.0.vulnerability.advisory_id,
                &self.0.vulnerability.advisory_identifier,
                self.0.vulnerability.advisory_type.as_deref(),
            )
            .into(),
            VerdictColumn::Status => html! {
                <div>
                    <span style="display: inline-flex; align-items: center; gap: var(--pf-t--global--spacer--sm); white-space: nowrap;">
                        {status_label(self.0.status)}
                        {confidence_label(&self.0.resolution)}
                        if self.0.evidence.iter().any(|e| !e.remediations.is_empty()) {
                            <Tooltip text="The advisories state a remediation, e.g. the version fixing the vulnerability">
                                <i class="fas fa-wrench" aria-label="Remediation available"/>
                            </Tooltip>
                        }
                    </span>
                </div>
            }.into(),
            VerdictColumn::Evidence => {
                html!(<Badge>{ self.0.evidence.len().to_string() }</Badge>).into()
            }
        }
    }

    fn actions(&self) -> Vec<MenuChildVariant> {
        vec![
            html_nested! {
                <Raw>
                    <ResolutionAction
                        target={PreviewTarget::Sbom{sbom_id:self.1}}
                        node_id={Some(self.0.component.node_id.clone())}
                        vulnerability_id={Some(self.0.vulnerability.id.clone())}/>
                </Raw>
            }
            .into(),
        ]
    }

    fn render_details(&self) -> Vec<Span> {
        let evidence = &self.0.evidence;
        if evidence.is_empty() {
            return vec![];
        }

        let remediations = self.remediations();

        let content = html! {
            <Stack gutter=true>
                <StackItem>
                    <Flex>
                        <FlexItem><Title level={Level::H4}>{ "Component in the SBOM" }</Title></FlexItem>
                        <FlexItem modifiers={[FlexModifier::Align(Alignment::Right)]}>
                            <ResolutionButton
                                target={PreviewTarget::Sbom{sbom_id:self.1}}
                                node_id={Some(self.0.component.node_id.clone())}
                                vulnerability_id={Some(self.0.vulnerability.id.clone())}/>
                        </FlexItem>
                    </Flex>
                    { identifiers(&self.0.component.identifiers) }
                    <div>
                        <strong>{ "Provider" }</strong>
                        <div>{ provider_view(&self.0.component_provider) }</div>
                    </div>
                </StackItem>
                <StackItem>
                    <Title level={Level::H4}>{ "Matched advisory assertions" }</Title>
                    <EvidenceTable evidence={evidence.clone()} />
                </StackItem>
                if !remediations.is_empty() {
                    <StackItem>
                        <Title level={Level::H4}>{ "Remediations" }</Title>
                        <ul class="pf-v6-c-list pf-m-plain">
                            { for remediations.iter().map(|(r, e)| html! {
                                <li>
                                    { remediation(r) }
                                    <span class="pf-v6-u-text-color-subtle pf-v6-u-ml-sm">
                                        { "(" }
                                        { advisory_link(e.advisory_id, &e.advisory_identifier, e.advisory_type.as_deref()) }
                                        { ")" }
                                    </span>
                                </li>
                            }) }
                        </ul>
                    </StackItem>
                }
            </Stack>
        };

        vec![Span::max(content)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum EvidenceColumn {
    Assertion,
    Confidence,
    Extractor,
    MatchedValue,
    Product,
    Provider,
    Advisory,
    Created,
}

#[derive(Clone, PartialEq)]
struct EvidenceEntry(EvidenceDetail);

impl TableEntryRenderer<EvidenceColumn> for EvidenceEntry {
    fn render_cell(&self, context: CellContext<'_, EvidenceColumn>) -> Cell {
        match context.column {
            EvidenceColumn::Assertion => html!(self.0.assertion_status.label()).into(),
            EvidenceColumn::Confidence => confidence_cell(
                &self.0.confidence_factors,
                &self.0.contexts,
                self.0.confidence,
            )
            .into(),
            EvidenceColumn::Extractor => html!(&self.0.extractor).into(),
            EvidenceColumn::MatchedValue => match &self.0.matched_value {
                Some(value) => matched_value(value).into(),
                None => html!("\u{2014}").into(),
            },
            EvidenceColumn::Product => product_names(&self.0.contexts).into(),
            EvidenceColumn::Provider => {
                let same = match self.0.provider_match {
                    Some(ProviderMatch::Provider) => Some(("Same as component", Color::Green)),
                    Some(ProviderMatch::Name) => Some(("Same name as component", Color::Blue)),
                    None => None,
                };
                html! {
                    <>
                        { provider_view(&self.0.provider) }
                        if let Some((label, color)) = same {
                            <div><Label compact=true {label} {color}/></div>
                        }
                    </>
                }
                .into()
            }
            EvidenceColumn::Advisory => advisory_link(
                self.0.advisory_id,
                &self.0.advisory_identifier,
                self.0.advisory_type.as_deref(),
            )
            .into(),
            EvidenceColumn::Created => timestamp(&self.0.created_at).into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct EvidenceTableProps {
    evidence: Vec<EvidenceDetail>,
}

#[function_component(EvidenceTable)]
fn evidence_table(props: &EvidenceTableProps) -> Html {
    let entries = use_memo(props.evidence.clone(), |evidence| {
        evidence
            .iter()
            .map(|e| EvidenceEntry(e.clone()))
            .collect::<Vec<_>>()
    });

    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<EvidenceColumn>>
            <TableColumn<EvidenceColumn> label="Assertion" index={EvidenceColumn::Assertion} />
            <TableColumn<EvidenceColumn> label="Confidence" index={EvidenceColumn::Confidence} />
            <TableColumn<EvidenceColumn> label="Extractor" index={EvidenceColumn::Extractor} />
            <TableColumn<EvidenceColumn> label="Matched Value" index={EvidenceColumn::MatchedValue} />
            <TableColumn<EvidenceColumn> label="Product" index={EvidenceColumn::Product} />
            <TableColumn<EvidenceColumn> label="Provider" index={EvidenceColumn::Provider} />
            <TableColumn<EvidenceColumn> label="Advisory" index={EvidenceColumn::Advisory} />
            <TableColumn<EvidenceColumn> label="Created" index={EvidenceColumn::Created} />
        </TableHeader<EvidenceColumn>>
    };

    html! {
        <Table<EvidenceColumn, UseTableData<EvidenceColumn, MemoizedTableModel<EvidenceEntry>>>
            mode={TableMode::Compact}
            {header}
            {entries}
        />
    }
}
