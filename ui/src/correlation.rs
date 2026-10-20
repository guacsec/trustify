use crate::{
    AppRoute,
    advisory::advisory_link,
    api,
    model::{
        ComponentRef, CorrelationResult, EvidenceDetail, EvidenceRemediation, IdentifierKind,
        IdentifierRef, MatchedValue, ProviderMatch, RemediationCategory, VerdictStatus,
        VerdictSummary,
    },
    resolution::{confidence_cell, product_names, provider_view},
};
use patternfly_yew::prelude::*;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use trustify_api::correlation::ResolutionSummary;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct CorrelationViewProps {
    pub sbom_id: String,
}

#[function_component(CorrelationView)]
pub fn correlation_view(props: &CorrelationViewProps) -> Html {
    let result = use_state(|| Option::<CorrelationResult>::None);
    let loading = use_state(|| true);
    let error = use_state(|| Option::<String>::None);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let sbom_id = props.sbom_id.clone();
        let result = result.clone();
        let loading = loading.clone();
        let error = error.clone();
        let token = token.clone();
        use_effect_with(sbom_id.clone(), move |id| {
            let id = id.clone();
            spawn_local(async move {
                loading.set(true);
                error.set(None);
                match api::fetch_correlation(&id, token.as_deref()).await {
                    Ok(data) => result.set(Some(data)),
                    Err(e) => error.set(Some(e.to_string())),
                }
                loading.set(false);
            });
        });
    }

    let sbom_id = &props.sbom_id;

    html! {
        <PageSection>
            <Breadcrumb>
                <BreadcrumbRouterItem<AppRoute> to={AppRoute::SbomList}>
                    { "SBOMs" }
                </BreadcrumbRouterItem<AppRoute>>
                <BreadcrumbItem>
                    { format!("Correlation: {sbom_id}") }
                </BreadcrumbItem>
            </Breadcrumb>

            if *loading {
                <Bullseye>
                    <Spinner />
                </Bullseye>
            } else if let Some(err) = &*error {
                <Alert title="Failed to load correlation" r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
            } else if let Some(data) = &*result {
                { crate::freshness::freshness_banner(&data.freshness) }
                <CorrelationContent
                    sbom_id={data.sbom_id}
                    verdicts={data.verdicts.clone()}
                    unmatched_components={data.unmatched_components.clone().unwrap_or_default()}
                />
            } else {
                <EmptyState
                    title="No data"
                    icon={Icon::Cubes}
                    size={Size::XXXXLarge}
                >
                    { "No correlation result available." }
                </EmptyState>
            }
        </PageSection>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct CorrelationContentProps {
    sbom_id: uuid::Uuid,
    verdicts: Vec<VerdictSummary>,
    unmatched_components: Vec<ComponentRef>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum VerdictColumn {
    Component,
    Vulnerability,
    Advisory,
    Status,
    Evidence,
}

#[derive(Clone, PartialEq)]
struct VerdictEntry(VerdictSummary, uuid::Uuid);

impl TableEntryRenderer<VerdictColumn> for VerdictEntry {
    fn render_cell(&self, context: CellContext<'_, VerdictColumn>) -> Cell {
        match context.column {
            VerdictColumn::Component => html! {
                <div>
                    { &self.0.component.name }
                    <div class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">
                        <code style="color: inherit; overflow-wrap: anywhere;">{ &self.0.component.node_id }</code>
                    </div>
                </div>
            }.into(),
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
                    <crate::resolution::ResolutionAction
                        target={trustify_api::correlation::PreviewTarget::Sbom{sbom_id:self.1}}
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

        // the remediations the advisories state for the evidence, each once per advisory
        let mut remediations = Vec::<(&EvidenceRemediation, &EvidenceDetail)>::new();
        for e in evidence {
            for r in &e.remediations {
                if !remediations
                    .iter()
                    .any(|(other, o)| *other == r && o.advisory_id == e.advisory_id)
                {
                    remediations.push((r, e));
                }
            }
        }

        let content = html! {
            <Stack gutter=true>
                <StackItem>
                    <Flex>
                        <FlexItem><Title level={Level::H4}>{ "Component in the SBOM" }</Title></FlexItem>
                        <FlexItem modifiers={[FlexModifier::Align(Alignment::Right)]}>
                            <crate::resolution::ResolutionButton
                                target={trustify_api::correlation::PreviewTarget::Sbom{sbom_id:self.1}}
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

#[derive(Copy, Clone, Eq, PartialEq)]
enum UnmatchedColumn {
    Name,
    Identifiers,
}

#[derive(Clone, PartialEq)]
struct UnmatchedEntry(ComponentRef);

impl TableEntryRenderer<UnmatchedColumn> for UnmatchedEntry {
    fn render_cell(&self, context: CellContext<'_, UnmatchedColumn>) -> Cell {
        match context.column {
            UnmatchedColumn::Name => html!(&self.0.name).into(),
            UnmatchedColumn::Identifiers => identifiers(&self.0.identifiers).into(),
        }
    }
}

/// The tabs of the correlation result of an SBOM.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CorrelationTab {
    Verdicts,
    Remediations,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemediationColumn {
    Component,
    Vulnerability,
    Status,
    Remediation,
    Advisory,
}

/// A remediation an advisory states for the statement of a verdict's evidence.
#[derive(Clone, PartialEq)]
struct RemediationEntry {
    component: ComponentRef,
    vulnerability: String,
    status: VerdictStatus,
    remediation: EvidenceRemediation,
    advisory_id: uuid::Uuid,
    advisory_identifier: String,
    advisory_type: Option<String>,
}

impl TableEntryRenderer<RemediationColumn> for RemediationEntry {
    fn render_cell(&self, context: CellContext<'_, RemediationColumn>) -> Cell {
        match context.column {
            RemediationColumn::Component => html! {
                <div>
                    { &self.component.name }
                    <div class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">
                        <code style="color: inherit; overflow-wrap: anywhere;">{ &self.component.node_id }</code>
                    </div>
                </div>
            }
            .into(),
            RemediationColumn::Vulnerability => html!(<strong>{ &self.vulnerability }</strong>).into(),
            RemediationColumn::Status => status_label(self.status).into(),
            RemediationColumn::Remediation => remediation(&self.remediation).into(),
            RemediationColumn::Advisory => advisory_link(
                self.advisory_id,
                &self.advisory_identifier,
                self.advisory_type.as_deref(),
            )
            .into(),
        }
    }
}

/// The remediations of the evidence of the verdicts, each once per component and vulnerability.
fn remediation_entries(verdicts: &[VerdictSummary]) -> Vec<RemediationEntry> {
    let mut result = Vec::<RemediationEntry>::new();
    for verdict in verdicts {
        for evidence in &verdict.evidence {
            for remediation in &evidence.remediations {
                let entry = RemediationEntry {
                    component: verdict.component.clone(),
                    vulnerability: verdict.vulnerability.id.clone(),
                    status: verdict.status,
                    remediation: remediation.clone(),
                    advisory_id: evidence.advisory_id,
                    advisory_identifier: evidence.advisory_identifier.clone(),
                    advisory_type: evidence.advisory_type.clone(),
                };
                if !result.contains(&entry) {
                    result.push(entry);
                }
            }
        }
    }
    result
}

/// A remediation, e.g. "Fixed in 4.1.2", or its category and details.
fn remediation(remediation: &EvidenceRemediation) -> Html {
    let text = match (&remediation.category, &remediation.details) {
        // a vendor fix's details already say what fixes it
        (RemediationCategory::VendorFix, Some(details)) => details.clone(),
        (category, Some(details)) => format!("{}: {details}", category.label()),
        (category, None) => category.label().to_string(),
    };
    html! {
        <span>
            <i class="fas fa-wrench pf-v6-u-mr-xs" aria-hidden="true"/>
            if let Some(url) = &remediation.url {
                <a href={url.clone()} target="_blank" rel="noopener noreferrer">{ text }</a>
            } else {
                { text }
            }
        </span>
    }
}

#[function_component(CorrelationContent)]
fn correlation_content(props: &CorrelationContentProps) -> Html {
    let tab = use_state_eq(|| CorrelationTab::Verdicts);
    let onselect = {
        let tab = tab.clone();
        Callback::from(move |index: CorrelationTab| tab.set(index))
    };
    let remediation_entries = use_memo(props.verdicts.clone(), |verdicts| {
        remediation_entries(verdicts)
    });
    let remediation_count = remediation_entries.len();
    let (remediation_entries, _) = use_table_data(MemoizedTableModel::new(remediation_entries));
    let remediation_header = html_nested! {
        <TableHeader<RemediationColumn>>
            <TableColumn<RemediationColumn> label="Component" index={RemediationColumn::Component} />
            <TableColumn<RemediationColumn> label="Vulnerability" index={RemediationColumn::Vulnerability} />
            <TableColumn<RemediationColumn> label="Status" index={RemediationColumn::Status} />
            <TableColumn<RemediationColumn> label="Remediation" index={RemediationColumn::Remediation} />
            <TableColumn<RemediationColumn> label="Advisory" index={RemediationColumn::Advisory} />
        </TableHeader<RemediationColumn>>
    };

    let has_verdicts = !props.verdicts.is_empty();
    let has_unmatched = !props.unmatched_components.is_empty();

    if !has_verdicts && !has_unmatched {
        return html! {
            <EmptyState
                title="No verdicts"
                icon={Icon::CheckCircle}
                size={Size::XXXXLarge}
            >
                { "No correlation matches found for this SBOM." }
            </EmptyState>
        };
    }

    let summary = verdict_summary_counts(&props.verdicts);

    let verdict_entries = use_memo(
        (props.verdicts.clone(), props.sbom_id),
        |(verdicts, sbom_id)| {
            verdicts
                .iter()
                .map(|v| VerdictEntry(v.clone(), *sbom_id))
                .collect::<Vec<_>>()
        },
    );

    let (verdict_entries, onexpand) = use_table_data(MemoizedTableModel::new(verdict_entries));

    let verdict_header = html_nested! {
        <TableHeader<VerdictColumn>>
            <TableColumn<VerdictColumn> label="Component" index={VerdictColumn::Component} />
            <TableColumn<VerdictColumn> label="Vulnerability" index={VerdictColumn::Vulnerability} />
            <TableColumn<VerdictColumn> label="Advisory" index={VerdictColumn::Advisory} />
            <TableColumn<VerdictColumn> label="Status" index={VerdictColumn::Status} />
            <TableColumn<VerdictColumn> label="Evidence" index={VerdictColumn::Evidence} />
        </TableHeader<VerdictColumn>>
    };

    let unmatched_entries = use_memo(props.unmatched_components.clone(), |components| {
        components
            .iter()
            .map(|c| UnmatchedEntry(c.clone()))
            .collect::<Vec<_>>()
    });

    let (unmatched_entries, _) = use_table_data(MemoizedTableModel::new(unmatched_entries));

    let unmatched_header = html_nested! {
        <TableHeader<UnmatchedColumn>>
            <TableColumn<UnmatchedColumn> label="Component" index={UnmatchedColumn::Name} />
            <TableColumn<UnmatchedColumn> label="Identifiers" index={UnmatchedColumn::Identifiers} />
        </TableHeader<UnmatchedColumn>>
    };

    let unmatched_count = props.unmatched_components.len();

    html! {
        <>
            <Gallery gutter=true>
                { for summary.iter().map(|(status, count)| html! {
                    <Card>
                        <CardBody>
                            <Flex space_items={[SpaceItems::Small]}
                                modifiers={[FlexModifier::Align(Alignment::Center)]}>
                                <FlexItem>
                                    { status_label(*status) }
                                </FlexItem>
                                <FlexItem>
                                    <Title level={Level::H3}>
                                        { count.to_string() }
                                    </Title>
                                </FlexItem>
                            </Flex>
                        </CardBody>
                    </Card>
                })}
                if has_unmatched {
                    <Card>
                        <CardBody>
                            <Flex space_items={[SpaceItems::Small]}
                                modifiers={[FlexModifier::Align(Alignment::Center)]}>
                                <FlexItem>
                                    <Label label="No Evidence" color={Color::Grey} />
                                </FlexItem>
                                <FlexItem>
                                    <Title level={Level::H3}>
                                        { unmatched_count.to_string() }
                                    </Title>
                                </FlexItem>
                            </Flex>
                        </CardBody>
                    </Card>
                }
            </Gallery>

            <br />

            <Tabs<CorrelationTab> selected={*tab} {onselect}>
            <Tab<CorrelationTab> index={CorrelationTab::Verdicts} title="Verdicts">
            <TabContent><TabContentBody padding=true>
            if has_verdicts {
                <Title level={Level::H2}>
                    { "Correlated components " }
                    <Badge>{ props.verdicts.len().to_string() }</Badge>
                </Title>
                <Table<VerdictColumn, UseTableData<VerdictColumn, MemoizedTableModel<VerdictEntry>>>
                    mode={TableMode::Expandable}
                    header={verdict_header}
                    entries={verdict_entries}
                    {onexpand}
                />
            }

            if has_unmatched {
                <br />
                <Title level={Level::H2}>
                    { "Unmatched components " }
                    <Badge>{ unmatched_count.to_string() }</Badge>
                </Title>
                <Table<UnmatchedColumn, UseTableData<UnmatchedColumn, MemoizedTableModel<UnmatchedEntry>>>
                    mode={TableMode::Compact}
                    header={unmatched_header}
                    entries={unmatched_entries}
                />
            }
            </TabContentBody></TabContent>
            </Tab<CorrelationTab>>
            <Tab<CorrelationTab> index={CorrelationTab::Remediations} title={format!("Remediations ({remediation_count})")}>
            <TabContent><TabContentBody padding=true>
            if remediation_count == 0 {
                <EmptyState title="No remediations" icon={Icon::InfoCircle} size={Size::Large}>
                    { "The advisories of the evidence state no remediation, such as a fixed version." }
                </EmptyState>
            } else {
                <p>{ "What the advisories state to remediate the vulnerabilities of the components, e.g. the version fixing them." }</p>
                <Table<RemediationColumn, UseTableData<RemediationColumn, MemoizedTableModel<RemediationEntry>>>
                    mode={TableMode::Compact}
                    header={remediation_header}
                    entries={remediation_entries}
                />
            }
            </TabContentBody></TabContent>
            </Tab<CorrelationTab>>
            </Tabs<CorrelationTab>>
        </>
    }
}

/// Render the identifiers of a component, grouped by kind.
fn identifiers(identifiers: &[IdentifierRef]) -> Html {
    let mut sections = BTreeMap::<IdentifierKind, Vec<&str>>::new();
    for identifier in identifiers {
        sections
            .entry(identifier.kind)
            .or_default()
            .push(&identifier.value);
    }

    if sections.is_empty() {
        return html!(<i>{ "\u{2014}" }</i>);
    }

    html! {
        { for sections.into_iter().map(|(kind, items)| html! {
            <div>
                <strong>{ kind.label() }</strong>
                <ul style="margin:0;padding-left:1em">
                    { for items.iter().map(|s| html!(<li><code>{ s }</code></li>)) }
                </ul>
            </div>
        })}
    }
}

/// Render the advisory side of a match: the identifier, and each matched version range on a line
/// of its own.
pub(crate) fn matched_value(value: &MatchedValue) -> Html {
    html! {
        <>
            <code>{ &value.identifier }</code>
            if !value.ranges.is_empty() {
                <ul style="margin:0;padding-left:1em">
                    { for value.ranges.iter().map(|range| html!(<li>{ range.to_string() }</li>)) }
                </ul>
            }
            if let Some(enabled_by) = &value.enabled_by {
                <div>
                    <small>
                        { "enabled by option " }
                        <code>{ enabled_by.key.as_str() }</code>
                        { " for " }
                        <code>{ &enabled_by.publisher_namespace }</code>
                        if let Some(reason) = &enabled_by.reason {
                            { ": " }{ reason }
                        }
                    </small>
                </div>
            }
        </>
    }
}

/// The label color of a verdict status.
/// A timestamp to the second, without the offset when in UTC. The tooltip has the full value.
pub(crate) fn timestamp(value: &OffsetDateTime) -> Html {
    let offset = value.offset();
    let mut short = format!(
        "{} {:02}:{:02}:{:02}",
        value.date(),
        value.hour(),
        value.minute(),
        value.second()
    );
    if !offset.is_utc() {
        let sign = if offset.is_negative() { '-' } else { '+' };
        short.push_str(&format!(
            " {sign}{:02}:{:02}",
            offset.whole_hours().unsigned_abs(),
            offset.minutes_past_hour().unsigned_abs()
        ));
    }
    html! {
        <Tooltip text={value.to_string()}>
            <span>{ short }</span>
        </Tooltip>
    }
}

/// The color of a verdict status, the same as of the statuses of advisories.
pub(crate) fn status_color(status: VerdictStatus) -> Color {
    match status {
        VerdictStatus::Affected => Color::Red,
        VerdictStatus::Fixed => Color::Blue,
        VerdictStatus::NotAffected => Color::Green,
        VerdictStatus::UnderInvestigation => Color::Orange,
        VerdictStatus::None => Color::Grey,
    }
}

/// The selected match confidence of a verdict as a label, e.g. "55%", explained on hover. A
/// conflict among the evidence is shown as a label of its own.
pub(crate) fn confidence_label(resolution: &ResolutionSummary) -> Html {
    let percent = format!("{:.0}%", resolution.confidence * 100.0);
    html! {
        <>
            <Tooltip text={format!("Confidence: {percent}")}>
                <Label compact=true outline=true label={percent.clone()} />
            </Tooltip>
            if resolution.has_conflict {
                <Tooltip text="Evidence states different statuses">
                    <Label compact=true color={Color::Orange} label="Conflict" />
                </Tooltip>
            }
        </>
    }
}

fn status_label(status: VerdictStatus) -> Html {
    html! { <Label label={status.label()} color={status_color(status)} /> }
}

fn verdict_summary_counts(verdicts: &[VerdictSummary]) -> Vec<(VerdictStatus, usize)> {
    let mut affected = 0usize;
    let mut fixed = 0usize;
    let mut not_affected = 0usize;
    let mut under_investigation = 0usize;
    let mut none = 0usize;

    for v in verdicts {
        match v.status {
            VerdictStatus::Affected => affected += 1,
            VerdictStatus::Fixed => fixed += 1,
            VerdictStatus::NotAffected => not_affected += 1,
            VerdictStatus::UnderInvestigation => under_investigation += 1,
            VerdictStatus::None => none += 1,
        }
    }

    let mut result = Vec::new();
    if affected > 0 {
        result.push((VerdictStatus::Affected, affected));
    }
    if fixed > 0 {
        result.push((VerdictStatus::Fixed, fixed));
    }
    if not_affected > 0 {
        result.push((VerdictStatus::NotAffected, not_affected));
    }
    if under_investigation > 0 {
        result.push((VerdictStatus::UnderInvestigation, under_investigation));
    }
    if none > 0 {
        result.push((VerdictStatus::None, none));
    }
    result
}
