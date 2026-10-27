//! Each collection owns its request, page state and table expansion state.
use super::*;
use serde::de::DeserializeOwned;
use trustify_api::correlation::SbomVerdictCounts;

#[derive(Clone, Debug, PartialEq, Properties)]
pub(super) struct CorrelationContentProps {
    pub sbom_id: uuid::Uuid,
}

struct Page<T> {
    items: Vec<T>,
    pagination: UsePagination,
    total: Option<usize>,
    loading: bool,
    error: Option<String>,
}

#[hook]
fn use_collection<T: Clone + PartialEq + DeserializeOwned + 'static>(
    sbom_id: uuid::Uuid,
    collection: &'static str,
    count_only: bool,
) -> Page<T> {
    let items = use_state_eq(Vec::<T>::new);
    let total = use_state_eq(|| None::<usize>);
    let loading = use_state_eq(|| true);
    let error = use_state_eq(|| None::<String>);
    let pagination = use_pagination(*total, || PaginationControl {
        page: 0,
        per_page: 25,
    });
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());
    {
        let (items, total, loading, error) =
            (items.clone(), total.clone(), loading.clone(), error.clone());
        use_effect_with(
            (sbom_id, collection, pagination.control, count_only, token),
            move |(sbom_id, collection, control, count_only, token)| {
                let (id, collection, control, count_only, token) = (
                    sbom_id.to_string(),
                    *collection,
                    *control,
                    *count_only,
                    token.clone(),
                );
                let cancelled = Rc::new(CancelFlag::new(false));
                let pending = cancelled.clone();
                loading.set(true);
                error.set(None);
                items.set(Vec::new());
                spawn_local(async move {
                    let response = api::fetch_correlation_page::<T>(
                        &id,
                        collection,
                        control.page * control.per_page,
                        if count_only { 0 } else { control.per_page },
                        true,
                        token.as_deref(),
                    )
                    .await;
                    if pending.get() {
                        return;
                    }
                    match response {
                        Ok(page) => {
                            total.set(page.total.and_then(|n| usize::try_from(n).ok()));
                            items.set(page.items);
                        }
                        Err(err) => error.set(Some(err.to_string())),
                    }
                    loading.set(false);
                });
                move || cancelled.set(true)
            },
        );
    }
    Page {
        items: (*items).clone(),
        pagination,
        total: *total,
        loading: *loading,
        error: (*error).clone(),
    }
}

fn page_status<T>(page: &Page<T>, empty: &'static str) -> Html {
    if page.loading {
        html!(<Spinner size={SpinnerSize::Md} />)
    } else if let Some(error) = &page.error {
        html!(<Alert title="Failed to load correlation data" r#type={AlertType::Danger} inline=true><p>{error}</p></Alert>)
    } else if page.items.is_empty() {
        html!(<EmptyState title={empty} icon={Icon::InfoCircle} size={Size::Large} />)
    } else {
        Html::default()
    }
}

#[function_component(CorrelationContent)]
pub(super) fn correlation_content(props: &CorrelationContentProps) -> Html {
    let tab = use_state_eq(|| CorrelationTab::Verdicts);
    let onselect = {
        let tab = tab.clone();
        Callback::from(move |index: CorrelationTab| tab.set(index))
    };
    html! {
        <>
            <CorrelationSummary sbom_id={props.sbom_id} />
            <br />
            <Tabs<CorrelationTab> selected={*tab} {onselect}>
                <Tab<CorrelationTab> index={CorrelationTab::Verdicts} title="Verdicts">
                    <TabContent><TabContentBody padding=true>
                        <VerdictTable sbom_id={props.sbom_id} />
                        <br />
                        <UnmatchedTable sbom_id={props.sbom_id} />
                    </TabContentBody></TabContent>
                </Tab<CorrelationTab>>
                <Tab<CorrelationTab> index={CorrelationTab::Remediations} title="Remediations">
                    <TabContent><TabContentBody padding=true>
                        <RemediationTable sbom_id={props.sbom_id} />
                    </TabContentBody></TabContent>
                </Tab<CorrelationTab>>
            </Tabs<CorrelationTab>>
        </>
    }
}

#[function_component(CorrelationSummary)]
fn correlation_summary(props: &CorrelationContentProps) -> Html {
    let counts = use_state_eq(|| None::<SbomVerdictCounts>);
    let error = use_state_eq(|| None::<String>);
    let unmatched = use_collection::<ComponentRef>(props.sbom_id, "/unmatched", true);
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());
    {
        let (counts, error) = (counts.clone(), error.clone());
        use_effect_with((props.sbom_id, token), move |(id, token)| {
            let (id, token) = (*id, token.clone());
            let cancelled = Rc::new(CancelFlag::new(false));
            let pending = cancelled.clone();
            spawn_local(async move {
                let response = api::count_verdicts(vec![id], token.as_deref()).await;
                if pending.get() {
                    return;
                }
                match response {
                    Ok(data) => counts.set(data.into_iter().next()),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
            move || cancelled.set(true)
        });
    }
    if let Some(error) = &*error {
        return html!(<Alert title="Failed to load SBOM summary" r#type={AlertType::Danger} inline=true><p>{error}</p></Alert>);
    }
    let Some(counts) = &*counts else {
        return html!(<Spinner size={SpinnerSize::Md} />);
    };
    let summary = [
        (VerdictStatus::Affected, counts.affected),
        (VerdictStatus::Fixed, counts.fixed),
        (VerdictStatus::NotAffected, counts.not_affected),
        (
            VerdictStatus::UnderInvestigation,
            counts.under_investigation,
        ),
        (VerdictStatus::None, counts.none),
    ];
    html! {
        <Gallery gutter=true>
            { for summary.into_iter().map(|(status, count)| html! {
                <Card><CardBody>{status_label(status)}<Title level={Level::H3}>{count.to_string()}</Title></CardBody></Card>
            }) }
            <Card><CardBody>
                <Label label="No Evidence" color={Color::Grey} />
                if let Some(count) = unmatched.total {
                    <Title level={Level::H3}>{count.to_string()}</Title>
                } else if unmatched.error.is_some() {
                    <p>{"Count unavailable"}</p>
                } else { <Spinner size={SpinnerSize::Md} /> }
            </CardBody></Card>
        </Gallery>
    }
}

#[function_component(VerdictTable)]
fn verdict_table(props: &CorrelationContentProps) -> Html {
    let page = use_collection::<VerdictSummary>(props.sbom_id, "", false);
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
            <Title level={Level::H2}>{"Correlated components "}<Badge>{page.total.map(|n| n.to_string()).unwrap_or_default()}</Badge></Title>
            <SimplePagination pagination={page.pagination.clone()} total={page.total} />
            {page_status(&page, "No verdicts found")}
            if !page.loading && page.error.is_none() && !page.items.is_empty() {
                <Table<VerdictColumn, UseTableData<VerdictColumn, MemoizedTableModel<VerdictEntry>>>
                    mode={TableMode::Expandable} {header} {entries} {onexpand}
                />
            }
        </>
    }
}

#[function_component(UnmatchedTable)]
fn unmatched_table(props: &CorrelationContentProps) -> Html {
    let page = use_collection::<ComponentRef>(props.sbom_id, "/unmatched", false);
    let rows = use_memo(page.items.clone(), |items| {
        items
            .iter()
            .cloned()
            .map(UnmatchedEntry)
            .collect::<Vec<_>>()
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(rows));
    let header = html_nested! {
        <TableHeader<UnmatchedColumn>>
            <TableColumn<UnmatchedColumn> label="Component" index={UnmatchedColumn::Name} />
            <TableColumn<UnmatchedColumn> label="Identifiers" index={UnmatchedColumn::Identifiers} />
        </TableHeader<UnmatchedColumn>>
    };
    html! {
        <>
            <Title level={Level::H2}>{"Unmatched components "}<Badge>{page.total.map(|n| n.to_string()).unwrap_or_default()}</Badge></Title>
            <SimplePagination pagination={page.pagination.clone()} total={page.total} />
            {page_status(&page, "No unmatched components")}
            if !page.loading && page.error.is_none() && !page.items.is_empty() {
                <Table<UnmatchedColumn, UseTableData<UnmatchedColumn, MemoizedTableModel<UnmatchedEntry>>>
                    mode={TableMode::Compact} {header} {entries}
                />
            }
        </>
    }
}

#[function_component(RemediationTable)]
fn remediation_table(props: &CorrelationContentProps) -> Html {
    let page = use_collection::<SbomRemediation>(props.sbom_id, "/remediations", false);
    let rows = use_memo(page.items.clone(), |items| {
        items
            .iter()
            .cloned()
            .map(RemediationEntry)
            .collect::<Vec<_>>()
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(rows));
    let header = html_nested! {
        <TableHeader<RemediationColumn>>
            <TableColumn<RemediationColumn> label="Component" index={RemediationColumn::Component} />
            <TableColumn<RemediationColumn> label="Vulnerability" index={RemediationColumn::Vulnerability} />
            <TableColumn<RemediationColumn> label="Status" index={RemediationColumn::Status} />
            <TableColumn<RemediationColumn> label="Remediation" index={RemediationColumn::Remediation} />
            <TableColumn<RemediationColumn> label="Advisory" index={RemediationColumn::Advisory} />
        </TableHeader<RemediationColumn>>
    };
    html! {
        <>
            <Title level={Level::H2}>{"Remediations "}<Badge>{page.total.map(|n| n.to_string()).unwrap_or_default()}</Badge></Title>
            <p>{"What the advisories state to remediate the vulnerabilities of the components, e.g. the version fixing them."}</p>
            <SimplePagination pagination={page.pagination.clone()} total={page.total} />
            {page_status(&page, "No remediations")}
            if !page.loading && page.error.is_none() && !page.items.is_empty() {
                <Table<RemediationColumn, UseTableData<RemediationColumn, MemoizedTableModel<RemediationEntry>>>
                    mode={TableMode::Compact} {header} {entries}
                />
            }
        </>
    }
}
