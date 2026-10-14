//! The list of advisories, searchable.

use crate::{AppRoute, advisory::AdvisoryFormat, api, sort::use_sort};
use patternfly_yew::prelude::*;
use trustify_client::api::types::AdvisorySummary;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::prelude::*;
use yew_oauth2::prelude::*;

#[derive(Copy, Clone, Eq, PartialEq)]
enum Column {
    Identifier,
    Format,
    Issuer,
    Published,
    Modified,
    Vulnerabilities,
}

#[derive(Clone, PartialEq)]
struct AdvisoryEntry(AdvisorySummary);

impl TableEntryRenderer<Column> for AdvisoryEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        let advisory = &self.0;
        match context.column {
            Column::Identifier => html! {
                <>
                    <strong>{ &advisory.identifier }</strong>
                    if let Some(title) = &advisory.title {
                        <br />
                        <small>{ title }</small>
                    }
                </>
            }
            .into(),
            Column::Format => {
                html!(<Label label={AdvisoryFormat::from_labels(&advisory.labels).label()} compact=true />)
                    .into()
            }
            Column::Issuer => html!(
                advisory
                    .issuer
                    .as_ref()
                    .map(|issuer| issuer.name.clone())
                    .unwrap_or_else(|| "-".into())
            )
            .into(),
            Column::Published => html!(date(advisory.published.map(|v| v.date_naive()))).into(),
            Column::Modified => html!(date(advisory.modified.map(|v| v.date_naive()))).into(),
            Column::Vulnerabilities => html!(advisory.vulnerabilities.len()).into(),
        }
    }
}

/// A date, or a placeholder.
fn date(value: Option<impl ToString>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}

/// The ID of an advisory without the `urn:uuid:` prefix the API returns it with.
fn advisory_id(advisory: &AdvisorySummary) -> String {
    advisory
        .uuid
        .strip_prefix("urn:uuid:")
        .unwrap_or(&advisory.uuid)
        .to_string()
}

/// The `sort` parameter of the advisory API for a column, `None` if the server can't sort by it.
fn sort_param(sortby: TableHeaderSortBy<Column>) -> Option<String> {
    let field = match sortby.index {
        Column::Identifier => "identifier",
        Column::Published => "published",
        Column::Modified => "modified",
        Column::Format | Column::Issuer | Column::Vulnerabilities => return None,
    };
    let order = match sortby.order {
        Order::Ascending => "asc",
        Order::Descending => "desc",
    };
    Some(format!("{field}:{order}"))
}

#[derive(Clone, PartialEq)]
enum Page {
    Loading,
    Ready {
        items: Vec<AdvisorySummary>,
        total: Option<usize>,
    },
    Failed(String),
}

#[function_component(AdvisoryList)]
pub fn advisory_list() -> Html {
    let page = use_state_eq(|| Page::Loading);
    let search = use_state_eq(String::new);
    let total = match &*page {
        Page::Ready { total, .. } => *total,
        _ => None,
    };
    let pagination = use_pagination(total, Default::default);
    let sort = use_sort::<Column>(None);
    let router = use_router::<AppRoute>();

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let page = page.clone();
        use_effect_with(
            ((*search).clone(), sort.sortby, pagination.control),
            move |(query, sortby, control)| {
                let query = query.clone();
                let sort = sortby.and_then(sort_param);
                let (offset, limit) = (control.page * control.per_page, control.per_page);
                spawn_local(async move {
                    page.set(Page::Loading);
                    let result = api::fetch_advisories(
                        &query,
                        sort.as_deref(),
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

    let onsearch = {
        let search = search.clone();
        Callback::from(move |value: String| search.set(value))
    };

    let entries = use_memo((*page).clone(), |page| match page {
        Page::Ready { items, .. } => items.iter().cloned().map(AdvisoryEntry).collect(),
        _ => Vec::new(),
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Advisory" index={Column::Identifier} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<Column> label="Format" index={Column::Format} />
            <TableColumn<Column> label="Issuer" index={Column::Issuer} />
            <TableColumn<Column> label="Published" index={Column::Published} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<Column> label="Modified" index={Column::Modified} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<Column> label="Vulnerabilities" index={Column::Vulnerabilities} />
        </TableHeader<Column>>
    };

    let onrowclick = Callback::from(move |entry: AdvisoryEntry| {
        if let Some(router) = &router {
            router.push(AppRoute::Advisory {
                id: advisory_id(&entry.0),
            });
        }
    });

    html! {
        <PageSection>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem>
                        <TextInput
                            placeholder="Search advisories..."
                            onchange={onsearch}
                            value={(*search).clone()}
                        />
                    </ToolbarItem>
                    <ToolbarItem r#type={ToolbarItemType::Pagination}>
                        <SimplePagination pagination={pagination.clone()} {total} />
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>

            {
                match &*page {
                    Page::Loading => html! {
                        <Bullseye>
                            <Spinner />
                        </Bullseye>
                    },
                    Page::Failed(err) => html! {
                        <Alert title="Failed to load advisories" r#type={AlertType::Danger} inline=true>
                            <p>{ err }</p>
                        </Alert>
                    },
                    Page::Ready { items, .. } if items.is_empty() => html! {
                        <EmptyState
                            title="No advisories found"
                            icon={Icon::Search}
                            size={Size::XXXXLarge}
                        >
                            { "Try adjusting your search or ingest some advisories first." }
                        </EmptyState>
                    },
                    Page::Ready { .. } => html! {
                        <>
                            <Table<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>
                                {header}
                                {entries}
                                {onrowclick}
                            />
                            <SimplePagination {pagination} {total} position={PaginationPosition::Bottom} />
                        </>
                    },
                }
            }
        </PageSection>
    }
}

#[cfg(test)]
mod test {
    use super::{Column, sort_param};
    use patternfly_yew::prelude::TableHeaderSortBy;

    #[test]
    fn sort_parameter() {
        assert_eq!(
            [
                TableHeaderSortBy::ascending(Column::Identifier),
                TableHeaderSortBy::descending(Column::Published),
                TableHeaderSortBy::ascending(Column::Issuer),
            ]
            .map(sort_param),
            [
                Some("identifier:asc".to_string()),
                Some("published:desc".to_string()),
                None,
            ]
        );
    }
}
