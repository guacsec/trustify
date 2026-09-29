use crate::api;
use patternfly_yew::prelude::*;
use trustify_api::correlation::{
    AssertionStatus, QueryMatch, QueryResult, QueryVerdict, VerdictStatus,
};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[function_component(QueryPage)]
pub fn query_page() -> Html {
    let result = use_state(|| Option::<QueryResult>::None);
    let loading = use_state(|| false);
    let error = use_state(|| Option::<String>::None);
    let input = use_state(String::new);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    let on_search = {
        let result = result.clone();
        let loading = loading.clone();
        let error = error.clone();
        let input = input.clone();
        let token = token.clone();
        Callback::from(move |_: ()| {
            let query = input.trim().to_string();
            if query.is_empty() {
                return;
            }
            let result = result.clone();
            let loading = loading.clone();
            let error = error.clone();
            let token = token.clone();
            spawn_local(async move {
                loading.set(true);
                error.set(None);
                match api::query_correlation(&query, token.as_deref()).await {
                    Ok(data) => result.set(Some(data)),
                    Err(e) => error.set(Some(e.to_string())),
                }
                loading.set(false);
            });
        })
    };

    let onsubmit = {
        let on_search = on_search.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            on_search.emit(());
        })
    };

    let onclick = {
        let on_search = on_search.clone();
        Callback::from(move |_: MouseEvent| {
            on_search.emit(());
        })
    };

    let onchange = {
        let input = input.clone();
        Callback::from(move |value: String| input.set(value))
    };

    html! {
        <PageSection>
            <Title level={Level::H1}>
                { "Identifier Query" }
            </Title>
            <p>{ "Search for advisories and vulnerabilities by model number, SKU, serial number, or digest." }</p>
            <br />

            <Form {onsubmit}>
                <FormGroup label="Identifier">
                    <TextInput
                        placeholder="Enter identifier (model number, SKU, digest, ...)"
                        value={(*input).clone()}
                        {onchange}
                    />
                </FormGroup>
                <ActionGroup>
                    <Button
                        variant={ButtonVariant::Primary}
                        label="Search"
                        {onclick}
                        loading={*loading}
                        disabled={*loading}
                    />
                </ActionGroup>
            </Form>

            <br />

            if *loading {
                <Bullseye>
                    <Spinner />
                </Bullseye>
            } else if let Some(err) = &*error {
                <Alert title="Query failed" r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
            } else if let Some(data) = &*result {
                <QueryResults data={data.clone()} />
            }
        </PageSection>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct QueryResultsProps {
    data: QueryResult,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum VerdictColumn {
    Vulnerability,
    Status,
    Evidence,
}

#[derive(Clone, PartialEq)]
struct VerdictEntry(QueryVerdict);

impl TableEntryRenderer<VerdictColumn> for VerdictEntry {
    fn render_cell(&self, context: CellContext<'_, VerdictColumn>) -> Cell {
        match context.column {
            VerdictColumn::Vulnerability => html! {
                <>
                    <strong>{ &self.0.vulnerability_id }</strong>
                    if let Some(title) = &self.0.vulnerability_title {
                        <br />
                        <small>{ title }</small>
                    }
                </>
            }
            .into(),
            VerdictColumn::Status => html!(status_label(self.0.status)).into(),
            VerdictColumn::Evidence => {
                html!(<Badge>{ self.0.matches.len().to_string() }</Badge>).into()
            }
        }
    }

    fn render_details(&self) -> Vec<Span> {
        if self.0.matches.is_empty() {
            return vec![];
        }

        let content = html! {
            <MatchTable matches={self.0.matches.clone()} />
        };

        vec![Span::max(content)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum MatchColumn {
    MatchType,
    Value,
    Advisory,
    Status,
}

#[derive(Clone, PartialEq)]
struct MatchEntry(QueryMatch);

impl TableEntryRenderer<MatchColumn> for MatchEntry {
    fn render_cell(&self, context: CellContext<'_, MatchColumn>) -> Cell {
        match context.column {
            MatchColumn::MatchType => html!(<Label label={self.0.match_type.label()} />).into(),
            MatchColumn::Value => html!(&self.0.value).into(),
            MatchColumn::Advisory => html!(&self.0.advisory_identifier).into(),
            MatchColumn::Status => html!(assertion_label(self.0.status)).into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct MatchTableProps {
    matches: Vec<QueryMatch>,
}

#[function_component(MatchTable)]
fn match_table(props: &MatchTableProps) -> Html {
    let entries = use_memo(props.matches.clone(), |matches| {
        matches
            .iter()
            .map(|m| MatchEntry(m.clone()))
            .collect::<Vec<_>>()
    });

    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<MatchColumn>>
            <TableColumn<MatchColumn> label="Type" index={MatchColumn::MatchType} />
            <TableColumn<MatchColumn> label="Matched Value" index={MatchColumn::Value} />
            <TableColumn<MatchColumn> label="Advisory" index={MatchColumn::Advisory} />
            <TableColumn<MatchColumn> label="Status" index={MatchColumn::Status} />
        </TableHeader<MatchColumn>>
    };

    html! {
        <Table<MatchColumn, UseTableData<MatchColumn, MemoizedTableModel<MatchEntry>>>
            mode={TableMode::Compact}
            {header}
            {entries}
        />
    }
}

#[function_component(QueryResults)]
fn query_results(props: &QueryResultsProps) -> Html {
    if props.data.verdicts.is_empty() {
        return html! {
            <EmptyState
                title="No matches"
                icon={Icon::Search}
                size={Size::XXXXLarge}
            >
                { format!("No advisories found matching \"{}\".", props.data.query) }
            </EmptyState>
        };
    }

    let summary = verdict_summary_counts(&props.data.verdicts);

    let entries = use_memo(props.data.verdicts.clone(), |verdicts| {
        verdicts
            .iter()
            .map(|v| VerdictEntry(v.clone()))
            .collect::<Vec<_>>()
    });

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<VerdictColumn>>
            <TableColumn<VerdictColumn> label="Vulnerability" index={VerdictColumn::Vulnerability} />
            <TableColumn<VerdictColumn> label="Verdict" index={VerdictColumn::Status} />
            <TableColumn<VerdictColumn> label="Evidence" index={VerdictColumn::Evidence} />
        </TableHeader<VerdictColumn>>
    };

    html! {
        <>
            <Title level={Level::H3}>
                { format!("{} verdict(s) for \"{}\"", props.data.verdicts.len(), props.data.query) }
            </Title>
            <br />

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

fn assertion_label(status: AssertionStatus) -> Html {
    let color = match status {
        AssertionStatus::Affected => Color::Red,
        AssertionStatus::Fixed => Color::Green,
        AssertionStatus::NotAffected => Color::Blue,
        AssertionStatus::UnderInvestigation => Color::Orange,
        AssertionStatus::Recommended => Color::Grey,
    };
    html! { <Label label={status.label()} {color} /> }
}

fn verdict_summary_counts(verdicts: &[QueryVerdict]) -> Vec<(VerdictStatus, usize)> {
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
