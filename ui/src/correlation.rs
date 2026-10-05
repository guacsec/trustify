use crate::{
    AppRoute, api,
    model::{
        ComponentRef, CorrelationResult, EvidenceDetail, IdentifierKind, VerdictStatus,
        VerdictSummary,
    },
};
use patternfly_yew::prelude::*;
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::components::Link;
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
                <CorrelationContent
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
struct VerdictEntry(VerdictSummary);

impl TableEntryRenderer<VerdictColumn> for VerdictEntry {
    fn render_cell(&self, context: CellContext<'_, VerdictColumn>) -> Cell {
        match context.column {
            VerdictColumn::Component => html!(&self.0.component.name).into(),
            VerdictColumn::Vulnerability => html! {
                <>
                    <strong>{ &self.0.vulnerability.id }</strong>
                    if let Some(title) = &self.0.vulnerability.title {
                        <br />
                        <small>{ title }</small>
                    }
                </>
            }
            .into(),
            VerdictColumn::Advisory => html! {
                <Link<AppRoute> to={AppRoute::Advisory { id: self.0.vulnerability.advisory_id.to_string() }}>
                    { &self.0.vulnerability.advisory_identifier }
                </Link<AppRoute>>
            }
            .into(),
            VerdictColumn::Status => html!(status_label(self.0.status)).into(),
            VerdictColumn::Evidence => {
                html!(<Badge>{ self.0.evidence.len().to_string() }</Badge>).into()
            }
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let evidence = &self.0.evidence;
        if evidence.is_empty() {
            return vec![];
        }

        let content = html! {
            <EvidenceTable evidence={evidence.clone()} />
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
    Advisory,
    Created,
}

#[derive(Clone, PartialEq)]
struct EvidenceEntry(EvidenceDetail);

impl TableEntryRenderer<EvidenceColumn> for EvidenceEntry {
    fn render_cell(&self, context: CellContext<'_, EvidenceColumn>) -> Cell {
        match context.column {
            EvidenceColumn::Assertion => html!(self.0.assertion_status.label()).into(),
            EvidenceColumn::Confidence => {
                html!(format!("{:.0}%", self.0.confidence * 100.0)).into()
            }
            EvidenceColumn::Extractor => html!(&self.0.extractor).into(),
            EvidenceColumn::MatchedValue => {
                html!(self.0.matched_value.as_deref().unwrap_or("\u{2014}")).into()
            }
            EvidenceColumn::Advisory => html! {
                <Link<AppRoute> to={AppRoute::Advisory { id: self.0.advisory_id.to_string() }}>
                    { &self.0.advisory_identifier }
                </Link<AppRoute>>
            }
            .into(),
            EvidenceColumn::Created => html!(&self.0.created_at).into(),
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
            UnmatchedColumn::Identifiers => {
                let mut sections = BTreeMap::<IdentifierKind, Vec<&str>>::new();
                for identifier in &self.0.identifiers {
                    sections
                        .entry(identifier.kind)
                        .or_default()
                        .push(&identifier.value);
                }

                let content: Vec<Html> = sections
                    .into_iter()
                    .map(|(kind, items)| {
                        html! {
                            <div>
                                <strong>{ kind.label() }</strong>
                                <ul style="margin:0;padding-left:1em">
                                    { for items.iter().map(|s| html!(<li>{ s }</li>)) }
                                </ul>
                            </div>
                        }
                    })
                    .collect();

                if content.is_empty() {
                    html!(<i>{ "\u{2014}" }</i>).into()
                } else {
                    html!({ for content }).into()
                }
            }
        }
    }
}

#[function_component(CorrelationContent)]
fn correlation_content(props: &CorrelationContentProps) -> Html {
    let has_verdicts = !props.verdicts.is_empty();
    let has_unmatched = !props.unmatched_components.is_empty();

    if !has_verdicts && !has_unmatched {
        return html! {
            <EmptyState
                title="No verdicts"
                icon={Icon::CheckCircle}
                size={Size::XXXXLarge}
            >
                { "No correlation evidence found for this SBOM. Run the correlation engine first." }
            </EmptyState>
        };
    }

    let summary = verdict_summary_counts(&props.verdicts);

    let verdict_entries = use_memo(props.verdicts.clone(), |verdicts| {
        verdicts
            .iter()
            .map(|v| VerdictEntry(v.clone()))
            .collect::<Vec<_>>()
    });

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
        </>
    }
}

/// The label color of a verdict status.
pub(crate) fn status_color(status: VerdictStatus) -> Color {
    match status {
        VerdictStatus::Affected => Color::Red,
        VerdictStatus::Fixed => Color::Green,
        VerdictStatus::NotAffected => Color::Blue,
        VerdictStatus::UnderInvestigation => Color::Orange,
        VerdictStatus::None => Color::Grey,
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
