use crate::{
    AppRoute, api,
    model::{CorrelationResult, EvidenceDetail, VerdictStatus, VerdictSummary},
};
use patternfly_yew::prelude::*;
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
                <CorrelationContent verdicts={data.verdicts.clone()} />
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
            VerdictColumn::Advisory => html!(&self.0.vulnerability.advisory_identifier).into(),
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
    Dimension,
    Assertion,
    Confidence,
    Extractor,
    Advisory,
    Created,
}

#[derive(Clone, PartialEq)]
struct EvidenceEntry(EvidenceDetail);

impl TableEntryRenderer<EvidenceColumn> for EvidenceEntry {
    fn render_cell(&self, context: CellContext<'_, EvidenceColumn>) -> Cell {
        match context.column {
            EvidenceColumn::Dimension => {
                html!(<Label label={self.0.match_dimension.label()} />).into()
            }
            EvidenceColumn::Assertion => html!(self.0.assertion_status.label()).into(),
            EvidenceColumn::Confidence => {
                html!(format!("{:.0}%", self.0.confidence * 100.0)).into()
            }
            EvidenceColumn::Extractor => html!(&self.0.extractor).into(),
            EvidenceColumn::Advisory => html!(&self.0.advisory_identifier).into(),
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
            <TableColumn<EvidenceColumn> label="Dimension" index={EvidenceColumn::Dimension} />
            <TableColumn<EvidenceColumn> label="Assertion" index={EvidenceColumn::Assertion} />
            <TableColumn<EvidenceColumn> label="Confidence" index={EvidenceColumn::Confidence} />
            <TableColumn<EvidenceColumn> label="Extractor" index={EvidenceColumn::Extractor} />
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

#[function_component(CorrelationContent)]
fn correlation_content(props: &CorrelationContentProps) -> Html {
    if props.verdicts.is_empty() {
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

    let entries = use_memo(props.verdicts.clone(), |verdicts| {
        verdicts
            .iter()
            .map(|v| VerdictEntry(v.clone()))
            .collect::<Vec<_>>()
    });

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<VerdictColumn>>
            <TableColumn<VerdictColumn> label="Component" index={VerdictColumn::Component} />
            <TableColumn<VerdictColumn> label="Vulnerability" index={VerdictColumn::Vulnerability} />
            <TableColumn<VerdictColumn> label="Advisory" index={VerdictColumn::Advisory} />
            <TableColumn<VerdictColumn> label="Status" index={VerdictColumn::Status} />
            <TableColumn<VerdictColumn> label="Evidence" index={VerdictColumn::Evidence} />
        </TableHeader<VerdictColumn>>
    };

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
            </Gallery>

            <br />

            <Table<VerdictColumn, UseTableData<VerdictColumn, MemoizedTableModel<VerdictEntry>>>
                mode={TableMode::Expandable}
                {header}
                {entries}
                {onexpand}
            />
        </>
    }
}

fn status_label(status: VerdictStatus) -> Html {
    let color = match status {
        VerdictStatus::Affected => Color::Red,
        VerdictStatus::Fixed => Color::Green,
        VerdictStatus::NotAffected => Color::Blue,
        VerdictStatus::UnderInvestigation => Color::Orange,
        VerdictStatus::None => Color::Grey,
    };
    html! { <Label label={status.label()} {color} /> }
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
