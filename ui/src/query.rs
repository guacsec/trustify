use crate::api;
use patternfly_yew::prelude::*;
use trustify_api::correlation::{AssertionStatus, QueryMatch, QueryResult};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Copy, Clone, Eq, PartialEq)]
enum MatchColumn {
    MatchType,
    Value,
    Vulnerability,
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
            MatchColumn::Vulnerability => html! {
                <>
                    <strong>{ &self.0.vulnerability_id }</strong>
                    if let Some(title) = &self.0.vulnerability_title {
                        <br />
                        <small>{ title }</small>
                    }
                </>
            }
            .into(),
            MatchColumn::Advisory => html!(&self.0.advisory_identifier).into(),
            MatchColumn::Status => html!(status_label(self.0.status)).into(),
        }
    }
}

fn status_label(status: AssertionStatus) -> Html {
    let color = match status {
        AssertionStatus::Affected => Color::Red,
        AssertionStatus::Fixed => Color::Green,
        AssertionStatus::NotAffected => Color::Blue,
        AssertionStatus::UnderInvestigation => Color::Orange,
        AssertionStatus::Recommended => Color::Grey,
    };
    html! { <Label label={status.label()} {color} /> }
}

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

#[function_component(QueryResults)]
fn query_results(props: &QueryResultsProps) -> Html {
    if props.data.matches.is_empty() {
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

    let entries = use_memo(props.data.matches.clone(), |matches| {
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
            <TableColumn<MatchColumn> label="Vulnerability" index={MatchColumn::Vulnerability} />
            <TableColumn<MatchColumn> label="Advisory" index={MatchColumn::Advisory} />
            <TableColumn<MatchColumn> label="Status" index={MatchColumn::Status} />
        </TableHeader<MatchColumn>>
    };

    html! {
        <>
            <Title level={Level::H3}>
                { format!("{} match(es) for \"{}\"", props.data.matches.len(), props.data.query) }
            </Title>
            <br />
            <Table<MatchColumn, UseTableData<MatchColumn, MemoizedTableModel<MatchEntry>>>
                {header}
                {entries}
            />
        </>
    }
}
