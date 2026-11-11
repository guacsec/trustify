//! Settings freshness and the automatically scheduled, durable background refreshes.
use crate::number::Number;
use crate::{AppRoute, api, correlation::timestamp, stored::use_stored_pagination};
use patternfly_yew::prelude::*;
use std::{cell::Cell, rc::Rc};
use time::{Duration, OffsetDateTime};
use trustify_api::correlation::*;
use uuid::Uuid;
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

fn freshness_badge(freshness: &ExtractionFreshness) -> Html {
    let color = match freshness.status {
        FreshnessStatus::Current => Color::Green,
        FreshnessStatus::Stale => Color::Orange,
        FreshnessStatus::Unknown => Color::Grey,
    };
    html! { <Label label={status_label(freshness.status)} {color} compact=true /> }
}

/// Whether `job` is refreshing results up to the revision `freshness` requires.
pub fn is_refreshing(job: Option<&RefreshJob>, freshness: &ExtractionFreshness) -> bool {
    job.is_some_and(|job| {
        matches!(
            job.status,
            RefreshJobStatus::Queued | RefreshJobStatus::Running
        ) && job.revision >= freshness.required_revision
    })
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Column {
    Sbom,
    Packages,
    Status,
    LastRefresh,
}

#[derive(Clone, PartialEq)]
struct View {
    overview: FreshnessOverview,
    documents: Vec<FreshnessDocument>,
    total: Option<usize>,
    /// Failures of the latest job, loaded only when it has any.
    failures: Option<RefreshJobDetails>,
    /// What the documents and failures were loaded for, to skip unchanged reloads.
    loaded: Loaded,
}

/// The inputs the documents and failures depend on. The overview is polled; the other
/// requests are only repeated when their inputs change.
#[derive(Clone, PartialEq)]
struct Loaded {
    documents: (usize, usize, i64, u64, u64, u64, u64),
    failures: Option<(Uuid, u64, usize)>,
}

impl Loaded {
    fn new(overview: &FreshnessOverview, offset: usize, limit: usize, failure_page: usize) -> Self {
        Self {
            // Document states change only together with these counters.
            documents: (
                offset,
                limit,
                overview.revision,
                overview.total,
                overview.current,
                overview.stale,
                overview.unknown,
            ),
            failures: overview
                .latest_job
                .as_ref()
                .filter(|job| job.failed > 0)
                .map(|job| (job.id, job.failed, failure_page)),
        }
    }
}

fn job_label(status: RefreshJobStatus) -> &'static str {
    match status {
        RefreshJobStatus::Queued => "Queued",
        RefreshJobStatus::Running => "Running",
        RefreshJobStatus::Completed => "Completed",
        RefreshJobStatus::Superseded => "Restarted for new settings",
    }
}

/// Whether the job is still queued or running.
fn is_active(job: &RefreshJob) -> bool {
    matches!(
        job.status,
        RefreshJobStatus::Queued | RefreshJobStatus::Running
    )
}

/// A coarse, human readable duration such as "about 2 h 15 min".
fn approximate(duration: Duration) -> String {
    let minutes = duration.whole_minutes();
    match minutes {
        ..1 => "less than a minute".to_string(),
        1..60 => format!("about {minutes} min"),
        60..1440 => format!("about {} h {} min", minutes / 60, minutes % 60),
        _ => format!("about {} d {} h", minutes / 1440, minutes % 1440 / 60),
    }
}

/// The remaining time of an active job, measured against the server's clock.
fn eta(job: &RefreshJob, checked_at: OffsetDateTime) -> String {
    match job.estimated_completion_at {
        Some(at) => format!("{} remaining", approximate(at - checked_at)),
        None => "Estimating remaining time…".to_string(),
    }
}

/// The progress of the active refresh job.
///
/// Documents ingested or invalidated while the job runs are added to its remaining work.
fn job_progress(job: &RefreshJob) -> Html {
    let done = job.processed + job.failed;
    let total = done + job.remaining;
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
        0 => format!("{} of {}", Number(done), Number(total)),
        failed => format!(
            "{} of {} ({} failed)",
            Number(done),
            Number(total),
            Number(failed)
        ),
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

/// The state of a processing stage, shown as a label in its card.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StageState {
    CaughtUp,
    Processing,
    Retrying,
    Unavailable,
}

impl StageState {
    /// Derive the state from outstanding and failed work.
    fn of(pending: u64, failed: u64) -> Self {
        match (pending, failed) {
            (_, 1..) => Self::Retrying,
            (0, 0) => Self::CaughtUp,
            _ => Self::Processing,
        }
    }

    /// Busy stages show no label: the pending count and progress already say so.
    fn label(self) -> Html {
        let (text, color) = match self {
            Self::CaughtUp => ("Caught up", Color::Green),
            Self::Processing => return Html::default(),
            Self::Retrying => ("Retrying failures", Color::Orange),
            Self::Unavailable => ("Unavailable", Color::Grey),
        };
        html! { <Label label={text} {color} compact=true /> }
    }
}

/// One processing stage: a headline count with its state, followed by details.
fn stage_card(title: &str, state: StageState, headline: String, details: Html) -> Html {
    html! {
        <GridItem cols={[12.all(), 4.lg()]}>
            <Card full_height=true>
                <CardHeader>
                    <Flex modifiers={[FlexModifier::Align(Alignment::Center), FlexModifier::Justify(Justify::SpaceBetween)]} >
                        <FlexItem><CardTitle>{ title }</CardTitle></FlexItem>
                        <FlexItem>{ state.label() }</FlexItem>
                    </Flex>
                </CardHeader>
                <CardBody>
                    <Stack gutter=true>
                        <StackItem><Title level={Level::H2}>{ headline }</Title></StackItem>
                        { details }
                    </Stack>
                </CardBody>
            </Card>
        </GridItem>
    }
}

/// What is being done with an SBOM, for how long, and how far it is, measured against the
/// server's clock.
fn current_document(action: &str, current: &CurrentSbom, checked_at: OffsetDateTime) -> Html {
    let id = current.sbom_id.to_string();
    let name = current.name.clone().unwrap_or_else(|| id.clone());
    let elapsed = checked_at - current.started_at;
    html! {
        <>
            <StackItem>
                { format!("{action} ") }
                <Link<AppRoute> to={AppRoute::Correlation { id }}>{ name }</Link<AppRoute>>
                { format!(", started {} ago", approximate(elapsed)) }
            </StackItem>
            if let Some(progress) = current.progress.filter(|p| p.total > 0) {
                <StackItem>
                    <Progress
                        value={progress.done as f64 / progress.total as f64}
                        description={remaining(progress, elapsed)}
                        value_text={format!("{} of {}", Number(progress.done), Number(progress.total))}
                        size={ProgressSize::Small}
                    />
                </StackItem>
            }
        </>
    }
}

/// The remaining time of a piece of work, extrapolated from its rate so far.
fn remaining(progress: WorkProgress, elapsed: Duration) -> String {
    if progress.done == 0 {
        return "Estimating remaining time…".to_string();
    }
    let left = progress.total.saturating_sub(progress.done) as f64 / progress.done as f64;
    format!("{} remaining", approximate(elapsed * left))
}

/// "Oldest pending: <timestamp>", or nothing when caught up.
fn oldest(label: &str, at: Option<&OffsetDateTime>) -> Html {
    match at {
        Some(at) => html! { <StackItem>{ label }{ ": " }{ timestamp(at) }</StackItem> },
        None => Html::default(),
    }
}

/// SBOM extraction: freshness against matching settings and the refresh job.
fn sbom_card(overview: &FreshnessOverview, job: Option<&RefreshJob>) -> Html {
    let active = job.filter(|job| is_active(job));
    let failed = active.map_or(0, |job| job.failed);
    let details = html! {
        <>
            if let Some(job) = active {
                <StackItem>{ job_progress(job) }</StackItem>
                <StackItem>{ eta(job, overview.checked_at) }</StackItem>
                { for job.current.iter().map(|current| current_document("Refreshing", current, overview.checked_at)) }
            } else if overview.needs_refresh > 0 {
                <StackItem>{ "Waiting to retry failed documents." }</StackItem>
            }
        </>
    };
    stage_card(
        "SBOM extraction",
        StageState::of(overview.needs_refresh, failed),
        format!("{} pending", Number(overview.needs_refresh)),
        details,
    )
}

/// How long the advisory rate is measured over.
const RATE_WINDOW: Duration = Duration::minutes(5);
/// How long the advisory rate must be measured for, to be meaningful.
const RATE_MINIMUM: Duration = Duration::seconds(30);

/// The number of pending advisories over time.
type PendingSamples = Vec<(OffsetDateTime, u64)>;

/// Add a sample, dropping the ones outside of the window.
fn add_sample(samples: &mut PendingSamples, at: OffsetDateTime, pending: u64) {
    samples.retain(|(sampled, _)| at - *sampled <= RATE_WINDOW);
    samples.push((at, pending));
}

/// Advisories finished per minute. Advisories added meanwhile raise the count, which isn't work
/// done, so only decreases count. `None` until there is enough to tell.
fn advisory_rate(samples: &[(OffsetDateTime, u64)]) -> Option<f64> {
    let (first, last) = (samples.first()?.0, samples.last()?.0);
    let span = last - first;
    if span < RATE_MINIMUM {
        return None;
    }
    let done = samples
        .windows(2)
        .map(|pair| pair[0].1.saturating_sub(pair[1].1))
        .sum::<u64>();
    Some(done as f64 / span.as_seconds_f64() * 60.0)
}

/// The rate of the advisory extraction, and how long the pending ones will take at that rate.
fn rate_text(rate: Option<f64>, pending: u64) -> Option<String> {
    if pending == 0 {
        return None;
    }
    Some(match rate {
        None => "Measuring the rate…".to_string(),
        Some(rate) if rate <= 0.0 => format!(
            "None finished in the last {} min",
            RATE_WINDOW.whole_minutes()
        ),
        Some(rate) => format!(
            "About {} per minute, {} remaining",
            Number(rate.round() as u64),
            approximate(Duration::seconds_f64(pending as f64 / rate * 60.0))
        ),
    })
}

/// Advisory extraction: the ingestion queue matching new advisories against SBOMs.
fn advisory_card(
    lag: Option<&ExtractionLag>,
    rate: Option<f64>,
    checked_at: OffsetDateTime,
) -> Html {
    let Some(lag) = lag else {
        return stage_card(
            "Advisory extraction",
            StageState::Unavailable,
            "–".into(),
            Html::default(),
        );
    };
    let details = html! {
        <>
            { for lag.current.iter().map(|current| html! {
                <StackItem>
                    { format!(
                        "Extracting {}, started {} ago",
                        current.identifier,
                        approximate(checked_at - current.started_at)
                    ) }
                </StackItem>
            }) }
            if let Some(text) = rate_text(rate, lag.pending_advisories) {
                <StackItem>{ text }</StackItem>
            }
            { oldest("Oldest pending change", lag.oldest_pending_at.as_ref()) }
            if lag.failed > 0 {
                <StackItem>{ format!("{} waiting for retry; see server logs.", Number(lag.failed)) }</StackItem>
            }
        </>
    };
    stage_card(
        "Advisory extraction",
        StageState::of(lag.pending_advisories, lag.failed),
        format!("{} pending", Number(lag.pending_advisories)),
        details,
    )
}

/// Verdict computation: snapshots resolved from the extracted evidence.
fn verdict_card(lag: &VerdictLag, checked_at: OffsetDateTime) -> Html {
    let details = html! {
        <>
            { for lag.current.iter().map(|current| current_document("Computing the verdicts of", current, checked_at)) }
            { oldest("Oldest outstanding work", lag.oldest_pending_at.as_ref()) }
            if lag.failed > 0 {
                <StackItem>{ format!("{} waiting for retry; see server logs.", Number(lag.failed)) }</StackItem>
            }
        </>
    };
    stage_card(
        "Verdicts",
        StageState::of(lag.pending, lag.failed),
        format!("{} pending", Number(lag.pending)),
        details,
    )
}

#[function_component(FreshnessPage)]
pub fn freshness_page() -> Html {
    let view = use_state(|| None::<View>);
    let error = use_state(|| None::<String>);
    let generation = use_state(|| 0u64);
    let in_flight = use_mut_ref(|| 0usize);
    // The last loaded view, readable by the request without re-running the effect.
    let last = use_mut_ref(|| None::<View>);
    let samples = use_mut_ref(PendingSamples::new);
    let rate = use_state(|| None::<f64>);
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
        let last = last.clone();
        let samples = samples.clone();
        let rate = rate.clone();
        use_effect_with(
            (
                *generation,
                pagination.control,
                *failure_page,
                token.clone(),
            ),
            move |(_, control, failure_page, _)| {
                let cancelled = Rc::new(Cell::new(false));
                let pending = cancelled.clone();
                *in_flight.borrow_mut() += 1;
                let (control, failure_page) = (*control, *failure_page);
                spawn_local(async move {
                    let previous = last.borrow().clone();
                    let loaded = async {
                        let overview = api::fetch_freshness(token.as_deref()).await?;
                        let (offset, limit) = (control.page * control.per_page, control.per_page);
                        let loaded = Loaded::new(&overview, offset, limit, failure_page);
                        let (documents, total) = match &previous {
                            Some(view) if view.loaded.documents == loaded.documents => {
                                (view.documents.clone(), view.total)
                            }
                            _ => {
                                let docs =
                                    api::fetch_freshness_documents(offset, limit, token.as_deref())
                                        .await?;
                                (docs.items, docs.total.map(|t| t as usize))
                            }
                        };
                        let failures = match (&previous, loaded.failures) {
                            (Some(view), Some(_)) if view.loaded.failures == loaded.failures => {
                                view.failures.clone()
                            }
                            (_, Some((job, _, page))) => Some(
                                api::fetch_refresh_job(job, page * 20, 20, token.as_deref())
                                    .await?,
                            ),
                            (_, None) => None,
                        };
                        Ok::<_, api::ApiError>(View {
                            overview,
                            documents,
                            total,
                            failures,
                            loaded,
                        })
                    }
                    .await;
                    *in_flight.borrow_mut() -= 1;
                    if !pending.get() {
                        match loaded {
                            Ok(data) => {
                                if let Some(lag) = &data.overview.extraction_lag {
                                    let mut samples = samples.borrow_mut();
                                    add_sample(
                                        &mut samples,
                                        data.overview.checked_at,
                                        lag.pending_advisories,
                                    );
                                    rate.set(advisory_rate(&samples));
                                }
                                *last.borrow_mut() = Some(data.clone());
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

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="SBOM" index={Column::Sbom} />
            <TableColumn<Column> label="Packages" index={Column::Packages} />
            <TableColumn<Column> label="Status" index={Column::Status} />
            <TableColumn<Column> label="Last successful refresh" index={Column::LastRefresh} />
        </TableHeader<Column>>
    };

    let checked = match &*view {
        Some(data) => html! { <>{ "Checked " }{ timestamp(&data.overview.checked_at) }</> },
        None => Html::default(),
    };

    html! {
        <PageSection>
            <Stack gutter=true>
            <StackItem>
                <Flex modifiers={[FlexModifier::Align(Alignment::Center), FlexModifier::Justify(Justify::SpaceBetween)]}>
                    <FlexItem><Title level={Level::H1}>{ "Correlation status" }</Title></FlexItem>
                    <FlexItem>{ checked }</FlexItem>
                </Flex>
                <p>{ "Ingested documents are processed automatically, also after matching settings change. Results show the latest completed computation." }</p>
            </StackItem>
            if let Some(err) = &*error {
                <StackItem>
                    <Alert title="Could not update correlation status" r#type={AlertType::Danger} inline=true><p>{err}</p><p>{"Previously loaded data is retained."}</p></Alert>
                </StackItem>
            }
            if let Some(data) = &*view {
                <StackItem>
                    <Grid gutter=true>
                        { sbom_card(&data.overview, data.overview.latest_job.as_ref()) }
                        { advisory_card(data.overview.extraction_lag.as_ref(), *rate, data.overview.checked_at) }
                        { verdict_card(&data.overview.verdict_lag, data.overview.checked_at) }
                    </Grid>
                </StackItem>
                if let Some(details) = data.failures.as_ref().filter(|details| details.failure_total > 0) {
                    <StackItem>
                        <Alert title={format!("{} documents could not be refreshed", Number(details.failure_total))} r#type={AlertType::Warning} inline=true>
                            <p>{"Their previous results remain available. Failed documents are retried automatically."}</p>
                            <ExpandableSection toggle_text_hidden="Show failures" toggle_text_expanded="Hide failures">
                                <ul>{for details.failures.iter().map(|f| html! {
                                    <li><Link<AppRoute> to={AppRoute::Correlation { id: f.sbom_id.to_string() }}>{ f.sbom_id.to_string() }</Link<AppRoute>>{format!(": {}", f.error)}</li>
                                })}</ul>
                                if details.failure_total > 20 {
                                    <Flex>
                                        <FlexItem><Button variant={ButtonVariant::Secondary} disabled={*failure_page == 0} onclick={{ let page = failure_page.clone(); Callback::from(move |_: MouseEvent| page.set(page.saturating_sub(1))) }}>{"Previous failures"}</Button></FlexItem>
                                        <FlexItem><Button variant={ButtonVariant::Secondary} disabled={((*failure_page + 1) * 20) as u64 >= details.failure_total} onclick={{ let page = failure_page.clone(); Callback::from(move |_: MouseEvent| page.set(*page + 1)) }}>{"Next failures"}</Button></FlexItem>
                                    </Flex>
                                }
                            </ExpandableSection>
                        </Alert>
                    </StackItem>
                }
                <StackItem>
                <Title level={Level::H2}>{ "Documents needing a refresh" }</Title>
                <Toolbar>
                    <ToolbarContent>
                        <ToolbarItem r#type={ToolbarItemType::Pagination}>
                            <SimplePagination pagination={pagination.clone()} {total} />
                        </ToolbarItem>
                    </ToolbarContent>
                </Toolbar>
                // the package counts
                <ComposableTable class="trustify-numeric-2">
                    { header }
                    <TableBody>
                        if data.documents.is_empty() {
                            <TableRow>
                                <TableData colspan={4}>
                                    <Bullseye>
                                        <EmptyState title="All documents are current" icon={Icon::CheckCircle} size={Size::Large}>
                                            { "No SBOMs need to be refreshed against the current matching settings." }
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
                                <TableData data_label="Packages">{ Number(doc.packages) }</TableData>
                                <TableData data_label="Status">{ freshness_badge(&doc.freshness) }</TableData>
                                <TableData data_label="Last successful refresh">
                                    { doc.freshness.completed_at.as_ref().map(timestamp).unwrap_or_else(|| html!("Never")) }
                                </TableData>
                            </TableRow>
                        }) }
                    </TableBody>
                </ComposableTable>
                </StackItem>
            } else if error.is_none() { <StackItem><Spinner /></StackItem> }
            </Stack>
        </PageSection>
    }
}

#[cfg(test)]
mod test {
    use super::{PendingSamples, add_sample, advisory_rate, approximate, rate_text};
    use time::{Duration, OffsetDateTime};

    #[test]
    fn advisory_rates() {
        let start = OffsetDateTime::UNIX_EPOCH;
        let mut samples = PendingSamples::new();
        add_sample(&mut samples, start, 1000);
        assert_eq!(advisory_rate(&samples), None);

        // added advisories aren't work done
        add_sample(&mut samples, start + Duration::seconds(30), 990);
        add_sample(&mut samples, start + Duration::seconds(60), 1500);
        add_sample(&mut samples, start + Duration::seconds(120), 1480);
        assert_eq!(advisory_rate(&samples), Some(15.0));

        // old samples drop out of the window
        add_sample(&mut samples, start + Duration::minutes(10), 1480);
        add_sample(&mut samples, start + Duration::minutes(11), 1480);
        assert_eq!(samples.len(), 2);
        assert_eq!(advisory_rate(&samples), Some(0.0));
    }

    #[test]
    fn rate_texts() {
        assert_eq!(rate_text(Some(15.0), 0), None);
        assert_eq!(rate_text(None, 5).as_deref(), Some("Measuring the rate…"));
        assert_eq!(
            rate_text(Some(0.0), 5).as_deref(),
            Some("None finished in the last 5 min")
        );
        assert!(
            rate_text(Some(15.0), 1800)
                .is_some_and(|text| text.ends_with("per minute, about 2 h 0 min remaining"))
        );
    }

    #[test]
    fn approximate_durations() {
        assert_eq!(
            [
                Duration::seconds(-5),
                Duration::seconds(59),
                Duration::minutes(42),
                Duration::minutes(135),
                Duration::hours(50),
            ]
            .map(approximate),
            [
                "less than a minute",
                "less than a minute",
                "about 42 min",
                "about 2 h 15 min",
                "about 2 d 2 h",
            ]
        );
    }
}
