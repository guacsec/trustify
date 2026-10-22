//! Settings freshness and manually initiated, durable background refreshes.
use crate::{AppRoute, api, stored::use_stored_pagination};
use patternfly_yew::prelude::*;
use std::{
    cell::Cell,
    fmt::{Display, Formatter},
    rc::Rc,
};
use trustify_api::correlation::*;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

pub fn status_label(status: FreshnessStatus) -> &'static str {
    match status {
        FreshnessStatus::Current => "Current",
        FreshnessStatus::Stale => "Outdated",
        FreshnessStatus::Unknown => "Not yet checked",
    }
}

/// Status filter of the documents table, where `None` selects all documents needing a refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DocumentFilter(Option<FreshnessStatus>);

impl DocumentFilter {
    const ALL: [Self; 2] = [Self(None), Self(Some(FreshnessStatus::Current))];
}

impl Display for DocumentFilter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            None => f.write_str("Needs refreshing"),
            Some(status) => f.write_str(status_label(status)),
        }
    }
}

fn freshness_badge(freshness: &ExtractionFreshness) -> Html {
    let color = match freshness.status {
        FreshnessStatus::Current => Color::Green,
        FreshnessStatus::Stale => Color::Orange,
        FreshnessStatus::Unknown => Color::Grey,
    };
    html! { <Label label={status_label(freshness.status)} {color} compact=true /> }
}

pub fn freshness_banner(freshness: &ExtractionFreshness) -> Html {
    let message = match freshness.status {
        FreshnessStatus::Current => return Html::default(),
        FreshnessStatus::Stale => {
            "Matching settings changed. These results may be incomplete or outdated."
        }
        FreshnessStatus::Unknown => {
            "These results have not been checked against current matching settings."
        }
    };
    html! {
        <Alert title={message} r#type={AlertType::Warning} inline=true>
            <Link<AppRoute> to={AppRoute::CorrelationStatus}>{ "View correlation status and refresh results" }</Link<AppRoute>>
        </Alert>
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Column {
    Sbom,
    Status,
    LastRefresh,
}

#[derive(Clone, PartialEq)]
struct View {
    overview: FreshnessOverview,
    documents: Vec<FreshnessDocument>,
    total: Option<usize>,
    job: Option<RefreshJobDetails>,
}

fn job_label(status: RefreshJobStatus) -> &'static str {
    match status {
        RefreshJobStatus::Queued => "Queued",
        RefreshJobStatus::Running => "Running",
        RefreshJobStatus::Completed => "Completed",
        RefreshJobStatus::Superseded => "Settings changed — start another refresh",
    }
}

/// The progress of the active refresh job, or an empty bar when no refresh is running.
///
/// The job does not record how many documents it will refresh. Failed documents stay
/// outdated, so the total is estimated as the processed documents plus those currently
/// needing a refresh.
fn job_progress(job: Option<&RefreshJob>, needs_refresh: u64) -> Html {
    let Some(job) = job.filter(|job| {
        matches!(
            job.status,
            RefreshJobStatus::Queued | RefreshJobStatus::Running
        )
    }) else {
        return html! {
            <Progress value={0.0} description="No refresh running" value_text="" size={ProgressSize::Small} />
        };
    };
    let done = job.processed + job.failed;
    let total = (job.processed + needs_refresh).max(done);
    let value = if total == 0 {
        1.0
    } else {
        done as f64 / total as f64
    };
    let variant = match job.failed {
        0 => ProgressVariant::Default,
        _ => ProgressVariant::Warning,
    };
    let value_text = match job.failed {
        0 => format!("{done} of {total}"),
        failed => format!("{done} of {total} ({failed} failed)"),
    };
    html! {
        <Progress
            {value}
            description={job_label(job.status)}
            {variant}
            {value_text}
            size={ProgressSize::Small}
        />
    }
}

#[function_component(FreshnessPage)]
pub fn freshness_page() -> Html {
    let view = use_state(|| None::<View>);
    let error = use_state(|| None::<String>);
    let starting = use_state(|| false);
    let generation = use_state(|| 0u64);
    let in_flight = use_mut_ref(|| 0usize);
    let filter = use_state(|| None::<FreshnessStatus>);
    let total = view.as_ref().and_then(|v| v.total);
    let pagination = use_stored_pagination("correlation-status", total);
    let failure_page = use_state(|| 0usize);
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let generation = generation.clone();
        let in_flight = in_flight.clone();
        use_effect_with((), move |_| {
            let timer = gloo_timers::callback::Interval::new(5000, move || {
                if !gloo_utils::document().hidden() && *in_flight.borrow() == 0 {
                    generation.set(js_sys::Date::now() as u64);
                }
            });
            move || drop(timer)
        });
    }

    {
        let view = view.clone();
        let error = error.clone();
        let token = token.clone();
        let in_flight = in_flight.clone();
        use_effect_with(
            (
                *generation,
                *filter,
                pagination.control,
                *failure_page,
                token.clone(),
            ),
            move |(_, filter, control, failure_page, _)| {
                let cancelled = Rc::new(Cell::new(false));
                let pending = cancelled.clone();
                *in_flight.borrow_mut() += 1;
                let (filter, control, failure_page) = (*filter, *control, *failure_page);
                spawn_local(async move {
                    let loaded = async {
                        let overview = api::fetch_freshness(token.as_deref()).await?;
                        let docs = api::fetch_freshness_documents(
                            filter,
                            control.page * control.per_page,
                            control.per_page,
                            token.as_deref(),
                        )
                        .await?;
                        let job = match &overview.latest_job {
                            Some(job) => Some(
                                api::fetch_refresh_job(
                                    job.id,
                                    failure_page * 20,
                                    20,
                                    token.as_deref(),
                                )
                                .await?,
                            ),
                            None => None,
                        };
                        Ok::<_, api::ApiError>(View {
                            overview,
                            documents: docs.items,
                            total: docs.total.map(|t| t as usize),
                            job,
                        })
                    }
                    .await;
                    *in_flight.borrow_mut() -= 1;
                    if !pending.get() {
                        match loaded {
                            Ok(data) => {
                                view.set(Some(data));
                                error.set(None);
                            }
                            Err(err) => error.set(Some(err.to_string())),
                        }
                    }
                });
                move || cancelled.set(true)
            },
        );
    }

    let start = {
        let starting = starting.clone();
        let error = error.clone();
        let generation = generation.clone();
        let failure_page = failure_page.clone();
        let token = token.clone();
        Callback::from(move |_: MouseEvent| {
            let (starting, error, generation, failure_page, token) = (
                starting.clone(),
                error.clone(),
                generation.clone(),
                failure_page.clone(),
                token.clone(),
            );
            starting.set(true);
            spawn_local(async move {
                match api::start_refresh(token.as_deref()).await {
                    Ok(_) => {
                        failure_page.set(0);
                        generation.set(js_sys::Date::now() as u64);
                    }
                    Err(err) => error.set(Some(format!("Could not start refresh: {err}"))),
                }
                starting.set(false);
            });
        })
    };

    let onfilter = {
        let filter = filter.clone();
        let pagination = pagination.clone();
        Callback::from(move |value: DocumentFilter| {
            filter.set(value.0);
            pagination.onnavigation.emit(Navigation::First);
        })
    };

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="SBOM" index={Column::Sbom} />
            <TableColumn<Column> label="Status" index={Column::Status} />
            <TableColumn<Column> label="Last successful refresh" index={Column::LastRefresh} />
        </TableHeader<Column>>
    };

    html! {
        <PageSection>
            <Title level={Level::H1}>{ "Correlation status" }</Title>
            <p>{ "Freshness against matching settings. Each SBOM is counted once, including documents with no matches. This status does not indicate whether newly ingested advisories have finished processing." }</p>
            if let Some(err) = &*error {
                <Alert title="Could not update correlation status" r#type={AlertType::Danger} inline=true><p>{err}</p><p>{"Previously loaded data is retained."}</p></Alert>
            }
            if let Some(data) = &*view {
                <Gallery gutter=true>
                    { for [("Current", data.overview.current), ("Needs refreshing", data.overview.needs_refresh)].into_iter().map(|(label, count)| html! {
                        <Card>
                            <CardBody>
                                <Flex space_items={[SpaceItems::Small]} modifiers={[FlexModifier::Align(Alignment::Center)]}>
                                    <FlexItem>{ label }</FlexItem>
                                    <FlexItem><Title level={Level::H3}>{ count.to_string() }</Title></FlexItem>
                                </Flex>
                            </CardBody>
                        </Card>
                    }) }
                </Gallery>
                <Flex modifiers={[FlexModifier::Align(Alignment::Center)]}>
                    <FlexItem><Title level={Level::H2}>{ "Refresh" }</Title></FlexItem>
                    <FlexItem modifiers={[FlexModifier::Align(Alignment::Right)]}>
                        <Button
                            variant={ButtonVariant::Primary}
                            onclick={start}
                            disabled={*starting || data.overview.active_job.is_some() || data.overview.needs_refresh == 0}
                        >
                            { "Refresh outdated results" }
                        </Button>
                    </FlexItem>
                </Flex>
                { job_progress(data.job.as_ref().map(|details| &details.job), data.overview.needs_refresh) }
                if let Some(details) = &data.job {
                    if details.failure_total > 0 {
                        <Alert title="Some documents could not be refreshed" r#type={AlertType::Warning} inline=true>{"Their previous results remain available. Start another refresh to retry documents still needing work."}</Alert>
                        <ul>{for details.failures.iter().map(|f| html! {
                            <li><Link<AppRoute> to={AppRoute::Correlation { id: f.sbom_id.to_string() }}>{ f.sbom_id.to_string() }</Link<AppRoute>>{format!(": {}", f.error)}</li>
                        })}</ul>
                        <Flex>
                            <FlexItem><Button variant={ButtonVariant::Secondary} disabled={*failure_page == 0} onclick={{ let page = failure_page.clone(); Callback::from(move |_: MouseEvent| page.set(page.saturating_sub(1))) }}>{"Previous failures"}</Button></FlexItem>
                            <FlexItem><Button variant={ButtonVariant::Secondary} disabled={((*failure_page + 1) * 20) as u64 >= details.failure_total} onclick={{ let page = failure_page.clone(); Callback::from(move |_: MouseEvent| page.set(*page + 1)) }}>{"Next failures"}</Button></FlexItem>
                        </Flex>
                    }
                }
                <Title level={Level::H2}>{ "Documents" }</Title>
                <Toolbar>
                    <ToolbarContent>
                        <ToolbarItem>
                            <ToggleGroup>
                                { for DocumentFilter::ALL.into_iter().map(|value| html_nested! {
                                    <ToggleGroupItem
                                        text={value.to_string()}
                                        selected={value == DocumentFilter(*filter)}
                                        onchange={onfilter.reform(move |()| value)}
                                    />
                                }) }
                            </ToggleGroup>
                        </ToolbarItem>
                        <ToolbarItem r#type={ToolbarItemType::Pagination}>
                            <SimplePagination pagination={pagination.clone()} {total} />
                        </ToolbarItem>
                    </ToolbarContent>
                </Toolbar>
                <ComposableTable>
                    { header }
                    <TableBody>
                        if data.documents.is_empty() {
                            <TableRow>
                                <TableData colspan={3}>
                                    <Bullseye>
                                        <EmptyState title="No documents found" icon={Icon::Search} size={Size::Large}>
                                            { "No SBOMs have this status. Select a different status to see other documents." }
                                        </EmptyState>
                                    </Bullseye>
                                </TableData>
                            </TableRow>
                        }
                        { for data.documents.iter().map(|doc| html! {
                            <TableRow key={doc.sbom_id.to_string()}>
                                <TableData data_label="SBOM">
                                    <Link<AppRoute> to={AppRoute::Correlation { id: doc.sbom_id.to_string() }}>{ &doc.name }</Link<AppRoute>>
                                </TableData>
                                <TableData data_label="Status">{ freshness_badge(&doc.freshness) }</TableData>
                                <TableData data_label="Last successful refresh">
                                    { doc.freshness.completed_at.map(|t| t.to_string()).unwrap_or_else(|| "Never".into()) }
                                </TableData>
                            </TableRow>
                        }) }
                    </TableBody>
                </ComposableTable>
            } else if error.is_none() { <Spinner /> }
        </PageSection>
    }
}
