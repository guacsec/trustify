//! Poll processing metadata without replacing the page the user is inspecting.
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
                    if let Some(completed) = state.completed_at { <span>{format!(" Computed at {completed}")}</span> }
                    if changed { <Button variant={ButtonVariant::Link} onclick={refresh}>{"Load updated results"}</Button> }
                </StackItem>
            }
            if let Some(data) = &*overview {
                <StackItem>
                    <p>{format!("Verdict processing: {} SBOMs outstanding, {} awaiting retry.", data.verdict_lag.pending, data.verdict_lag.failed)}</p>
                    if let Some(oldest) = data.verdict_lag.oldest_pending_at { <p>{format!("Oldest verdict work: {oldest}")}</p> }
                    if let Some(lag) = &data.extraction_lag {
                        <p>{format!("Extraction: {} advisory changes and {} SBOM changes outstanding, {} awaiting retry.", lag.pending_advisories, lag.pending_sboms, lag.failed)}</p>
                        if let Some(oldest) = lag.oldest_pending_at { <p>{format!("Oldest extraction work: {oldest}")}</p> }
                    }
                    if data.needs_refresh > 0 { <p>{format!("{} SBOMs need extraction refreshed against current settings.", data.needs_refresh)}</p> }
                    <p>{format!("Status checked at {}. Searches use the latest completed results.", data.checked_at)}</p>
                    <Link<AppRoute> to={AppRoute::CorrelationStatus}>{"View processing status"}</Link<AppRoute>>
                </StackItem>
            }
        </Stack>
    }
}
