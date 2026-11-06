//! Poll processing metadata without replacing the page the user is inspecting.
//!
//! Following the PatternFly alert guidelines, a page shows its status in a single bordered inline
//! alert below its title, and no alert once everything is current.
use super::timestamp;
use crate::number::Number;
use crate::{AppRoute, api, freshness::is_refreshing};
use gloo_timers::callback::Interval;
use patternfly_yew::prelude::*;
use std::{cell::Cell, rc::Rc};
use trustify_api::correlation::{
    FreshnessOverview, FreshnessStatus, SbomVerdictCounts, VerdictFreshness,
};
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

/// Processing metadata, polled every five seconds.
#[derive(Clone, Default, PartialEq)]
struct Polled {
    overview: Option<FreshnessOverview>,
    /// The latest counts of the SBOM, including the freshness of its extraction and verdicts.
    counts: Option<SbomVerdictCounts>,
    error: Option<String>,
}

/// Poll the processing overview, and the counts of an SBOM if given.
#[hook]
fn use_polled(sbom_id: Option<Uuid>) -> Polled {
    let polled = use_state_eq(Polled::default);
    let tick = use_state(|| 0_u64);
    let pending = use_mut_ref(|| false);
    let token = use_latest_access_token()
        .as_ref()
        .and_then(|t| t.access_token());
    {
        let (tick, pending) = (tick.clone(), pending.clone());
        use_effect_with((), move |_| {
            let timer = Interval::new(5000, move || {
                if !*pending.borrow() {
                    tick.set(js_sys::Date::now() as u64);
                }
            });
            move || drop(timer)
        });
    }
    {
        let (polled, pending) = (polled.clone(), pending.clone());
        use_effect_with((sbom_id, token, *tick), move |(sbom, token, _)| {
            let (sbom, token) = (*sbom, token.clone());
            let cancelled = Rc::new(Cell::new(false));
            let cancel = cancelled.clone();
            *pending.borrow_mut() = true;
            spawn_local(async move {
                let response = async {
                    let overview = api::fetch_freshness(token.as_deref()).await?;
                    let counts = match sbom {
                        Some(id) => api::count_verdicts(vec![id], token.as_deref())
                            .await?
                            .into_iter()
                            .next(),
                        None => None,
                    };
                    Ok::<_, api::ApiError>((overview, counts))
                }
                .await;
                *pending.borrow_mut() = false;
                if cancel.get() {
                    return;
                }
                polled.set(match response {
                    Ok((overview, counts)) => Polled {
                        overview: Some(overview),
                        counts,
                        error: None,
                    },
                    // keep showing the last known state
                    Err(err) => Polled {
                        error: Some(err.to_string()),
                        ..(*polled).clone()
                    },
                });
            });
            move || cancelled.set(true)
        });
    }
    (*polled).clone()
}

/// The outstanding background work of all documents, for pages listing them.
#[function_component(ProcessingStatus)]
pub fn processing_status() -> Html {
    let polled = use_polled(None);
    let outstanding = polled.overview.as_ref().and_then(outstanding);
    html! {
        <div aria-live="polite">
            if let Some(error) = &polled.error {
                <Alert title="Could not update processing status" r#type={AlertType::Warning} inline=true><p>{error}</p></Alert>
            } else if let Some(outstanding) = outstanding {
                <Alert title="Correlation results are being updated" r#type={AlertType::Info} inline=true>
                    <p>{ outstanding }{ ". " }<Link<AppRoute> to={AppRoute::CorrelationStatus}>{"View processing status"}</Link<AppRoute>></p>
                </Alert>
            }
        </div>
    }
}

/// Properties of [`SbomStatus`].
#[derive(Clone, PartialEq, Properties)]
pub struct SbomStatusProps {
    pub sbom_id: Uuid,
    /// The freshness of the verdicts the page shows.
    #[prop_or_default]
    pub shown: Option<VerdictFreshness>,
    /// Reload the page's results.
    #[prop_or_default]
    pub onreload: Callback<()>,
}

/// The status of an SBOM's results, as one alert, or the time they were computed once they are
/// current.
#[function_component(SbomStatus)]
pub fn sbom_status(props: &SbomStatusProps) -> Html {
    let polled = use_polled(Some(props.sbom_id));
    let Some(counts) = &polled.counts else {
        return html! {
            if let Some(error) = &polled.error {
                <Alert title="Could not load the correlation status" r#type={AlertType::Warning} inline=true><p>{error}</p></Alert>
            }
        };
    };
    let overview = polled.overview.as_ref();
    let completed = props
        .shown
        .as_ref()
        .and_then(|shown| shown.completed_at)
        .or(counts.verdict_freshness.completed_at);
    let computed = completed.map(|completed| html!(<>{"Computed at "}{ timestamp(&completed) }</>));
    let Some(state) = sbom_state(props.shown.as_ref(), counts, overview) else {
        return html! {
            <div aria-live="polite">
                if let Some(computed) = computed {
                    <p><small>{ computed }</small></p>
                }
            </div>
        };
    };
    let outstanding = overview.and_then(outstanding);
    let actions = match state {
        SbomState::Newer => vec![Action::new("Load updated results", props.onreload.clone())],
        _ => Vec::new(),
    };
    html! {
        <div aria-live="polite">
            <Alert title={state.title()} r#type={state.alert_type()} inline=true {actions}>
                <p>
                    if let Some(description) = state.description() { { description }{ " " } }
                    if let Some(outstanding) = outstanding { { outstanding }{ ". " } }
                    if let Some(computed) = computed { { computed }{ ". " } }
                    <Link<AppRoute> to={AppRoute::CorrelationStatus}>{"View processing status"}</Link<AppRoute>>
                </p>
            </Alert>
            if polled.error.is_some() {
                <Alert title="Could not update the correlation status" r#type={AlertType::Warning} inline=true plain=true />
            }
        </div>
    }
}

/// The state of an SBOM's results, most important first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SbomState {
    /// Newer verdicts were computed since the page loaded.
    Newer,
    /// No verdicts were computed yet.
    NotComputed,
    /// A refresh job extracts the SBOM against the current matching settings.
    Refreshing,
    /// The matching settings changed since the SBOM was extracted, and no job refreshes it.
    SettingsChanged,
    /// The SBOM was never extracted against the current matching settings, and no job does.
    Unchecked,
    /// The inputs of the verdicts changed, and they are being recomputed.
    Recomputing,
    /// The results are current, but background work, which may affect them, is outstanding.
    Updating,
}

impl SbomState {
    fn title(self) -> String {
        match self {
            Self::Newer => "Newer results available",
            Self::NotComputed => "Verdicts not computed yet",
            Self::Refreshing => "Results are being refreshed",
            Self::SettingsChanged => "Matching settings changed",
            Self::Unchecked => "Results not checked against the current matching settings",
            Self::Recomputing => "Verdicts are being recomputed",
            Self::Updating => "Correlation results are being updated",
        }
        .to_string()
    }

    fn description(self) -> Option<&'static str> {
        match self {
            Self::SettingsChanged | Self::Unchecked => {
                Some("These results may be incomplete or outdated.")
            }
            _ => None,
        }
    }

    /// Warning when the results are outdated and nothing updates them, information otherwise.
    fn alert_type(self) -> AlertType {
        match self {
            Self::SettingsChanged | Self::Unchecked => AlertType::Warning,
            _ => AlertType::Info,
        }
    }
}

/// The most important state of an SBOM's results, or `None` once they are current and no
/// background work is outstanding.
fn sbom_state(
    shown: Option<&VerdictFreshness>,
    counts: &SbomVerdictCounts,
    overview: Option<&FreshnessOverview>,
) -> Option<SbomState> {
    let latest = &counts.verdict_freshness;
    if latest.generation.is_some()
        && shown.is_some_and(|shown| shown.generation != latest.generation)
    {
        return Some(SbomState::Newer);
    }
    if latest.generation.is_none() {
        return Some(SbomState::NotComputed);
    }
    let job = overview.and_then(|overview| overview.active_job.as_ref());
    match counts.freshness.status {
        FreshnessStatus::Current => {}
        _ if is_refreshing(job, &counts.freshness) => return Some(SbomState::Refreshing),
        FreshnessStatus::Stale => return Some(SbomState::SettingsChanged),
        FreshnessStatus::Unknown => return Some(SbomState::Unchecked),
    }
    if latest.status != FreshnessStatus::Current {
        return Some(SbomState::Recomputing);
    }
    overview.and_then(outstanding).map(|_| SbomState::Updating)
}

/// Summarizes outstanding background work, or nothing once processing has caught up.
fn outstanding(overview: &FreshnessOverview) -> Option<String> {
    let mut parts = Vec::new();
    let verdicts = &overview.verdict_lag;
    if verdicts.pending > 0 {
        parts.push(format!(
            "{} awaiting verdicts",
            count(verdicts.pending, "SBOM", "SBOMs")
        ));
    }
    let mut failed = verdicts.failed;
    if let Some(lag) = &overview.extraction_lag {
        if lag.pending_advisories > 0 {
            parts.push(format!(
                "{} awaiting extraction",
                count(
                    lag.pending_advisories,
                    "advisory change",
                    "advisory changes"
                )
            ));
        }
        failed += lag.failed;
    }
    if overview.needs_refresh > 0 {
        parts.push(format!(
            "{} refreshing against current settings",
            count(overview.needs_refresh, "SBOM", "SBOMs")
        ));
    }
    if parts.is_empty() {
        return None;
    }
    let mut text = parts.join(", ");
    if failed > 0 {
        text.push_str(&format!(" ({} awaiting retry)", Number(failed)));
    }
    Some(text)
}

fn count(value: u64, singular: &str, plural: &str) -> String {
    format!(
        "{} {}",
        Number(value),
        if value == 1 { singular } else { plural }
    )
}

#[cfg(test)]
mod test {
    use super::{SbomState, outstanding, sbom_state};
    use time::OffsetDateTime;
    use trustify_api::correlation::{
        ExtractionFreshness, ExtractionLag, FreshnessOverview, FreshnessStatus, RefreshJob,
        RefreshJobStatus, SbomVerdictCounts, VerdictFreshness, VerdictLag,
    };
    use uuid::Uuid;

    fn overview(
        verdict_lag: VerdictLag,
        extraction_lag: Option<ExtractionLag>,
    ) -> FreshnessOverview {
        FreshnessOverview {
            revision: 1,
            checked_at: OffsetDateTime::UNIX_EPOCH,
            total: 10,
            current: 10,
            stale: 0,
            unknown: 0,
            needs_refresh: 0,
            extraction_lag,
            verdict_lag,
            active_job: None,
            latest_job: None,
        }
    }

    /// Nothing is shown once all background work has caught up.
    #[test]
    fn caught_up() {
        assert_eq!(
            outstanding(&overview(
                VerdictLag::default(),
                Some(ExtractionLag::default())
            )),
            None
        );
    }

    /// Outstanding work is summarized in one line, with retries of both stages combined.
    #[test]
    fn outstanding_work() {
        let mut data = overview(
            VerdictLag {
                pending: 1,
                failed: 1,
                oldest_pending_at: None,
                ..Default::default()
            },
            Some(ExtractionLag {
                pending_advisories: 5,
                failed: 2,
                oldest_pending_at: None,
                current: vec![],
            }),
        );
        data.needs_refresh = 2;
        assert_eq!(
            outstanding(&data).as_deref(),
            Some(
                "1 SBOM awaiting verdicts, 5 advisory changes awaiting extraction, \
                 2 SBOMs refreshing against current settings (3 awaiting retry)"
            )
        );
    }

    fn verdicts(status: FreshnessStatus, generation: Option<u128>) -> VerdictFreshness {
        VerdictFreshness {
            status,
            generation: generation.map(Uuid::from_u128),
            completed_at: None,
            required_revision: 1,
            completed_revision: generation.map(|_| 1),
        }
    }

    fn counts(extraction: FreshnessStatus, verdicts: VerdictFreshness) -> SbomVerdictCounts {
        SbomVerdictCounts {
            sbom_id: Uuid::nil(),
            freshness: ExtractionFreshness {
                status: extraction,
                required_revision: 2,
                completed_revision: Some(1),
                completed_at: None,
            },
            verdict_freshness: verdicts,
            affected: 0,
            fixed: 0,
            not_affected: 0,
            under_investigation: 0,
            none: 0,
            remediations: 0,
        }
    }

    fn refreshing() -> FreshnessOverview {
        let mut data = overview(VerdictLag::default(), None);
        data.active_job = Some(RefreshJob {
            id: Uuid::nil(),
            revision: 2,
            status: RefreshJobStatus::Running,
            processed: 0,
            failed: 0,
            remaining: 1,
            estimated_completion_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            finished_at: None,
            current: vec![],
        });
        data
    }

    /// The most important state wins, and nothing is shown once everything is current.
    #[test]
    fn sbom_states() {
        use FreshnessStatus::*;
        let current = verdicts(Current, Some(1));
        let caught_up = overview(VerdictLag::default(), None);
        let busy = overview(
            VerdictLag {
                pending: 1,
                ..Default::default()
            },
            None,
        );
        let cases = [
            // newer verdicts than the shown ones, even while not current
            (
                Some(verdicts(Current, Some(1))),
                counts(Stale, verdicts(Stale, Some(2))),
                &busy,
                Some(SbomState::Newer),
            ),
            (
                None,
                counts(Unknown, verdicts(Unknown, None)),
                &refreshing(),
                Some(SbomState::NotComputed),
            ),
            (
                Some(current.clone()),
                counts(Stale, current.clone()),
                &refreshing(),
                Some(SbomState::Refreshing),
            ),
            (
                Some(current.clone()),
                counts(Stale, current.clone()),
                &caught_up,
                Some(SbomState::SettingsChanged),
            ),
            (
                Some(current.clone()),
                counts(Unknown, current.clone()),
                &caught_up,
                Some(SbomState::Unchecked),
            ),
            (
                Some(verdicts(Stale, Some(1))),
                counts(Current, verdicts(Stale, Some(1))),
                &caught_up,
                Some(SbomState::Recomputing),
            ),
            (
                Some(current.clone()),
                counts(Current, current.clone()),
                &busy,
                Some(SbomState::Updating),
            ),
            (
                Some(current.clone()),
                counts(Current, current.clone()),
                &caught_up,
                None,
            ),
            // while the verdicts load, the latest ones are assumed to be shown
            (None, counts(Current, current.clone()), &caught_up, None),
        ];
        for (shown, counts, overview, expected) in cases {
            assert_eq!(
                sbom_state(shown.as_ref(), &counts, Some(overview)),
                expected,
                "{shown:?}"
            );
        }
    }
}
