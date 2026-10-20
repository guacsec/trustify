//! Settings freshness and manually initiated, durable background refreshes.
use crate::{AppRoute, api, stored::use_stored_pagination};
use patternfly_yew::prelude::*;
use std::{cell::Cell, rc::Rc};
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

pub fn freshness_badge(freshness: &ExtractionFreshness) -> Html {
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

    let selected_filter = match *filter {
        None => "needs_refresh",
        Some(FreshnessStatus::Stale) => "stale",
        Some(FreshnessStatus::Unknown) => "unknown",
        Some(FreshnessStatus::Current) => "current",
    };
    let onfilter = {
        let filter = filter.clone();
        let pagination = pagination.clone();
        Callback::from(move |value: Option<String>| {
            let value = match value.as_deref() {
                Some("stale") => Some(FreshnessStatus::Stale),
                Some("unknown") => Some(FreshnessStatus::Unknown),
                Some("current") => Some(FreshnessStatus::Current),
                _ => None,
            };
            filter.set(value);
            pagination.onnavigation.emit(Navigation::First);
        })
    };

    html! {
        <PageSection>
            <Title level={Level::H1}>{ "Correlation status" }</Title>
            <p>{ "Freshness against matching settings. Each SBOM is counted once, including documents with no matches. This status does not indicate whether newly ingested advisories have finished processing." }</p>
            if let Some(err) = &*error {
                <Alert title="Could not update correlation status" r#type={AlertType::Danger} inline=true><p>{err}</p><p>{"Previously loaded data is retained."}</p></Alert>
            }
            if let Some(data) = &*view {
                <div class="pf-v6-l-grid pf-m-gutter pf-v6-u-my-md">
                    { for [("Total SBOMs", data.overview.total), ("Current", data.overview.current), ("Outdated", data.overview.stale), ("Not yet checked", data.overview.unknown), ("Needs refreshing", data.overview.needs_refresh)].into_iter().map(|(label, count)| html! {
                        <section class="pf-v6-c-card pf-m-2-col"><div class="pf-v6-c-card__title">{label}</div><div class="pf-v6-c-card__body"><strong>{count}</strong></div></section>
                    }) }
                </div>
                <p>{ format!("Last checked: {}", data.overview.checked_at) }</p>
                <Button onclick={start} disabled={*starting || data.overview.active_job.is_some() || data.overview.needs_refresh == 0}>{ "Refresh outdated results" }</Button>
                if let Some(details) = &data.job {
                    <Title level={Level::H2}>{ "Latest refresh" }</Title>
                    <p role="status">{format!("{} · {} processed · {} failed · {} SBOMs currently need refreshing", job_label(details.job.status), details.job.processed, details.job.failed, data.overview.needs_refresh)}</p>
                    if details.failure_total > 0 {
                        <Alert title="Some documents could not be refreshed" r#type={AlertType::Warning} inline=true>{"Their previous results remain available. Start another refresh to retry documents still needing work."}</Alert>
                        <ul>{for details.failures.iter().map(|f| html! {
                            <li><Link<AppRoute> to={AppRoute::Correlation { id: f.sbom_id.to_string() }}>{ f.sbom_id.to_string() }</Link<AppRoute>>{format!(": {}", f.error)}</li>
                        })}</ul>
                        <Button variant={ButtonVariant::Secondary} disabled={*failure_page == 0} onclick={{ let page = failure_page.clone(); Callback::from(move |_: MouseEvent| page.set(page.saturating_sub(1))) }}>{"Previous failures"}</Button>
                        <Button variant={ButtonVariant::Secondary} disabled={((*failure_page + 1) * 20) as u64 >= details.failure_total} onclick={{ let page = failure_page.clone(); Callback::from(move |_: MouseEvent| page.set(*page + 1)) }}>{"Next failures"}</Button>
                    }
                }
                <Title level={Level::H2}>{ "Documents" }</Title>
                <Toolbar>
                    <ToolbarContent>
                        <ToolbarGroup variant={GroupVariant::Filter}>
                            <ToolbarItem>
                                <label for="correlation-document-status">{ "Status" }</label>
                            </ToolbarItem>
                            <ToolbarItem>
                                <FormSelect<String>
                                    id="correlation-document-status"
                                    value={selected_filter.to_string()}
                                    onchange={onfilter}
                                >
                                    <FormSelectOption<String> value="needs_refresh" description="Needs refreshing" />
                                    <FormSelectOption<String> value="stale" description="Outdated" />
                                    <FormSelectOption<String> value="unknown" description="Not yet checked" />
                                    <FormSelectOption<String> value="current" description="Current" />
                                </FormSelect<String>>
                            </ToolbarItem>
                        </ToolbarGroup>
                        <ToolbarItem r#type={ToolbarItemType::Pagination}>
                            <SimplePagination pagination={pagination.clone()} {total} />
                        </ToolbarItem>
                    </ToolbarContent>
                </Toolbar>
                if data.documents.is_empty() {
                    <p>{ "No documents in this category." }</p>
                } else {
                    <table class="pf-v6-c-table" aria-label="SBOM correlation freshness">
                        <thead><tr><th scope="col">{"SBOM"}</th><th scope="col">{"Status"}</th><th scope="col">{"Last successful refresh"}</th></tr></thead>
                        <tbody>{for data.documents.iter().map(|doc| html! {
                            <tr key={doc.sbom_id.to_string()}>
                                <td><Link<AppRoute> to={AppRoute::Correlation { id: doc.sbom_id.to_string() }}>{&doc.name}</Link<AppRoute>></td>
                                <td>{freshness_badge(&doc.freshness)}</td>
                                <td>{doc.freshness.completed_at.map(|t| t.to_string()).unwrap_or_else(|| "Never".into())}</td>
                            </tr>
                        })}</tbody>
                    </table>
                }
            } else if error.is_none() { <Spinner /> }
        </PageSection>
    }
}
