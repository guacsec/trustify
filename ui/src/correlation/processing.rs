//! Poll processing metadata without replacing the page the user is inspecting.
use super::timestamp;
use crate::{AppRoute, api};
use gloo_timers::callback::Interval;
use patternfly_yew::prelude::*;
use std::{cell::Cell, rc::Rc};
use trustify_api::correlation::{
    FreshnessOverview, FreshnessStatus, VerdictFreshness, VerdictSummary,
};
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

/// Processing metadata for an optional displayed verdict generation.
#[derive(Clone, PartialEq, Properties)]
pub struct ProcessingStatusProps {
    #[prop_or_default]
    pub sbom_id: Option<Uuid>,
    #[prop_or_default]
    pub snapshot: Option<VerdictFreshness>,
    #[prop_or_default]
    pub onrefresh: Callback<()>,
}

/// Keep freshness and backlog visible, while preserving expanded rows until requested.
#[function_component(ProcessingStatus)]
pub fn processing_status(props: &ProcessingStatusProps) -> Html {
    let overview = use_state(|| None::<FreshnessOverview>);
    let latest = use_state(|| None::<VerdictFreshness>);
    let error = use_state(|| None::<String>);
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
        let (overview, latest, error, pending) = (
            overview.clone(),
            latest.clone(),
            error.clone(),
            pending.clone(),
        );
        use_effect_with((props.sbom_id, token, *tick), move |(sbom, token, _)| {
            let (sbom, token) = (*sbom, token.clone());
            let cancelled = Rc::new(Cell::new(false));
            let cancel = cancelled.clone();
            *pending.borrow_mut() = true;
            spawn_local(async move {
                let response = async {
                    let overview = api::fetch_freshness(token.as_deref()).await?;
                    let freshness = match sbom {
                        Some(id) => {
                            api::fetch_correlation_page::<VerdictSummary>(
                                &id.to_string(),
                                "",
                                0,
                                0,
                                false,
                                token.as_deref(),
                            )
                            .await?
                            .freshness
                        }
                        None => None,
                    };
                    Ok::<_, api::ApiError>((overview, freshness))
                }
                .await;
                *pending.borrow_mut() = false;
                if cancel.get() {
                    return;
                }
                match response {
                    Ok((data, freshness)) => {
                        overview.set(Some(data));
                        latest.set(freshness);
                        error.set(None);
                    }
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
            move || cancelled.set(true)
        });
    }
    let changed = props
        .snapshot
        .as_ref()
        .zip(latest.as_ref())
        .is_some_and(|(old, new)| old.generation != new.generation);
    let state = if changed {
        props.snapshot.as_ref()
    } else {
        latest.as_ref().or(props.snapshot.as_ref())
    };
    let refresh = props.onrefresh.reform(|_: MouseEvent| ());
    html! {
        <Stack gutter=true>
            if let Some(err) = &*error {
                <Alert title="Could not update processing status" r#type={AlertType::Warning} inline=true><p>{err}</p></Alert>
            }
            if let Some(state) = state {
                <StackItem>
                    <Label label={if changed { "Newer results available" } else { match state.status { FreshnessStatus::Current => "Verdicts current", FreshnessStatus::Stale => "Verdicts stale", FreshnessStatus::Unknown => "Verdicts not computed yet" } }} />
                    if let Some(completed) = &state.completed_at { <span>{" Computed at "}{ timestamp(completed) }</span> }
                    if changed { <Button variant={ButtonVariant::Link} onclick={refresh}>{"Load updated results"}</Button> }
                </StackItem>
            }
            if let Some(outstanding) = (*overview).as_ref().and_then(outstanding) {
                <StackItem>
                    <Alert title="Correlation results are being updated" r#type={AlertType::Info} inline=true>
                        <p>{ outstanding }{ ". Results show the latest completed computation. " }<Link<AppRoute> to={AppRoute::CorrelationStatus}>{"View processing status"}</Link<AppRoute>></p>
                    </Alert>
                </StackItem>
            }
        </Stack>
    }
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
        if lag.pending_sboms > 0 {
            parts.push(format!(
                "{} awaiting extraction",
                count(lag.pending_sboms, "SBOM change", "SBOM changes")
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
        text.push_str(&format!(" ({failed} awaiting retry)"));
    }
    Some(text)
}

fn count(value: u64, singular: &str, plural: &str) -> String {
    format!("{value} {}", if value == 1 { singular } else { plural })
}

#[cfg(test)]
mod test {
    use super::outstanding;
    use time::OffsetDateTime;
    use trustify_api::correlation::{ExtractionLag, FreshnessOverview, VerdictLag};

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
            },
            Some(ExtractionLag {
                pending_advisories: 5,
                pending_sboms: 0,
                failed: 2,
                oldest_pending_at: None,
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
}
