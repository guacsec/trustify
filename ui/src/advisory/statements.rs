//! The statuses an advisory states for a vulnerability, as stored in the database: the facts
//! correlation matches SBOMs against.

use crate::{
    api,
    model::{AdvisoryStatement, MatchedRange, RangeBound, StatementKind, StatementSubject},
};
use patternfly_yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct VulnerabilityStatementsProps {
    pub advisory_id: AttrValue,
    pub vulnerability: AttrValue,
}

/// The statements for a vulnerability, one table per kind of subject.
#[function_component(VulnerabilityStatements)]
pub fn vulnerability_statements(props: &VulnerabilityStatementsProps) -> Html {
    html! {
        <Stack gutter=true>
            { for StatementKind::ALL.into_iter().map(|kind| html! {
                <StackItem>
                    <StatementTable
                        advisory_id={props.advisory_id.clone()}
                        vulnerability={props.vulnerability.clone()}
                        {kind}
                    />
                </StackItem>
            }) }
        </Stack>
    }
}

fn kind_title(kind: StatementKind) -> &'static str {
    match kind {
        StatementKind::Purl => "Packages (PURL)",
        StatementKind::Cpe => "Platforms (CPE)",
        StatementKind::Product => "Products",
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct StatementTableProps {
    advisory_id: AttrValue,
    vulnerability: AttrValue,
    kind: StatementKind,
}

#[derive(Clone, PartialEq)]
enum Page {
    Loading,
    Ready {
        items: Vec<AdvisoryStatement>,
        total: Option<usize>,
    },
    Failed(String),
}

/// One kind of statements, paginated on the server. Hidden when there are none.
#[function_component(StatementTable)]
fn statement_table(props: &StatementTableProps) -> Html {
    let page = use_state_eq(|| Page::Loading);
    let total = match &*page {
        Page::Ready { total, .. } => *total,
        _ => None,
    };
    let pagination = use_pagination(total, Default::default);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let page = page.clone();
        use_effect_with(
            (
                props.advisory_id.clone(),
                props.vulnerability.clone(),
                props.kind,
                pagination.control,
            ),
            move |(advisory_id, vulnerability, kind, control)| {
                let (advisory_id, vulnerability, kind) =
                    (advisory_id.clone(), vulnerability.clone(), *kind);
                let (offset, limit) = (control.page * control.per_page, control.per_page);
                spawn_local(async move {
                    let result = api::fetch_advisory_statements(
                        &advisory_id,
                        &vulnerability,
                        kind,
                        offset,
                        limit,
                        token.as_deref(),
                    )
                    .await;
                    page.set(match result {
                        Ok(result) => Page::Ready {
                            items: result.items,
                            total: result.total.and_then(|total| usize::try_from(total).ok()),
                        },
                        Err(err) => Page::Failed(err.to_string()),
                    });
                });
            },
        );
    }

    let entries = use_memo((*page).clone(), |page| match page {
        Page::Ready { items, .. } => items.iter().cloned().map(StatementEntry).collect(),
        _ => Vec::new(),
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let title = kind_title(props.kind);

    match &*page {
        Page::Loading => html!(<Spinner size={SpinnerSize::Md} />),
        Page::Failed(err) => html! {
            <Alert title={format!("Failed to load {}", title.to_lowercase())} r#type={AlertType::Danger} inline=true>
                <p>{ err }</p>
            </Alert>
        },
        Page::Ready { total: Some(0), .. } => html!(),
        Page::Ready { total, .. } => {
            let header = html_nested! {
                <TableHeader<StatementColumn>>
                    <TableColumn<StatementColumn> label="Status" index={StatementColumn::Status} />
                    <TableColumn<StatementColumn> label="Subject" index={StatementColumn::Subject} />
                    <TableColumn<StatementColumn> label="Versions" index={StatementColumn::Versions} />
                </TableHeader<StatementColumn>>
            };
            html! {
                <>
                    <Title level={Level::H4}>
                        { title } { " " }
                        <Badge>{ total.map(|total| total.to_string()).unwrap_or_default() }</Badge>
                    </Title>
                    if total.is_some_and(|total| total > pagination.control.per_page) {
                        <SimplePagination pagination={pagination.clone()} {total} />
                    }
                    <Table<StatementColumn, UseTableData<StatementColumn, MemoizedTableModel<StatementEntry>>>
                        mode={TableMode::Compact}
                        {header}
                        {entries}
                    />
                </>
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StatementColumn {
    Status,
    Subject,
    Versions,
}

#[derive(Clone, PartialEq)]
struct StatementEntry(AdvisoryStatement);

impl TableEntryRenderer<StatementColumn> for StatementEntry {
    fn render_cell(&self, context: CellContext<'_, StatementColumn>) -> Cell {
        match context.column {
            StatementColumn::Status => html! {
                <>
                    { status_label(&self.0.status) }
                    if self.0.default {
                        { " " }
                        <Label label="default" compact=true />
                    }
                </>
            }
            .into(),
            StatementColumn::Subject => subject(&self.0.subject).into(),
            StatementColumn::Versions => html!(<code>{ range(&self.0.range) }</code>).into(),
        }
    }
}

/// A label for a stated status (slug), e.g. `first_fixed`.
fn status_label(status: &str) -> Html {
    let color = match status {
        "affected" | "first_affected" | "last_affected" => Color::Red,
        "under_investigation" => Color::Orange,
        "not_affected" => Color::Green,
        "fixed" | "first_fixed" => Color::Blue,
        "recommended" => Color::Purple,
        _ => Color::Grey,
    };
    html!(<Label label={status.replace('_', " ")} {color} compact=true />)
}

fn subject(subject: &StatementSubject) -> Html {
    match subject {
        StatementSubject::Purl { purl } => html!(<code>{ purl }</code>),
        StatementSubject::Cpe { cpe } => html!(<code>{ cpe }</code>),
        StatementSubject::Product {
            name,
            cpe_key,
            package,
            csaf_product_ids,
        } => html! {
            <>
                { name }
                if let Some(cpe_key) = cpe_key {
                    <br />
                    <small>{ "CPE key: " }<code>{ cpe_key }</code></small>
                }
                if let Some(package) = package {
                    <br />
                    <small>{ "Package: " }<code>{ package }</code></small>
                }
                if !csaf_product_ids.is_empty() {
                    <br />
                    <small>{ "CSAF product IDs: " }<code>{ csaf_product_ids.join(", ") }</code></small>
                }
            </>
        },
    }
}

/// A version range for humans, e.g. `rpm: >= 1.0, < 2.0`. An empty version, as stored for a
/// versionless PURL, is shown as `""`.
fn range(range: &MatchedRange) -> String {
    let version = |bound: &RangeBound| match bound.version.as_str() {
        "" => "\"\"".to_string(),
        version => version.to_string(),
    };
    let low = |bound: &RangeBound| {
        format!(
            "{} {}",
            if bound.inclusive { ">=" } else { ">" },
            version(bound)
        )
    };
    let high = |bound: &RangeBound| {
        format!(
            "{} {}",
            if bound.inclusive { "<=" } else { "<" },
            version(bound)
        )
    };

    let versions = match (&range.low, &range.high) {
        (Some(l), Some(h)) if l == h && l.inclusive => format!("= {}", version(l)),
        (Some(l), Some(h)) => format!("{}, {}", low(l), high(h)),
        (Some(l), None) => low(l),
        (None, Some(h)) => high(h),
        (None, None) => "any version".to_string(),
    };
    format!("{}: {versions}", range.scheme)
}
