//! SBOM-wide verdict counts and extraction freshness.
use super::{CorrelationContentProps, common::status_label, pagination::use_collection};
use crate::{
    api,
    freshness::{freshness_banner, is_refreshing},
    model::{ComponentRef, VerdictStatus},
};
use patternfly_yew::prelude::*;
use std::{cell::Cell as CancelFlag, rc::Rc};
use trustify_api::correlation::SbomVerdictCounts;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

/// Show counts and freshness independently of the selected collection pages.
#[function_component(CorrelationSummary)]
pub(super) fn correlation_summary(props: &CorrelationContentProps) -> Html {
    let counts = use_state_eq(|| None::<SbomVerdictCounts>);
    let error = use_state_eq(|| None::<String>);
    let tick = use_state_eq(|| 0_u64);
    {
        let tick = tick.clone();
        use_effect_with((), move |_| {
            let timer = gloo_timers::callback::Interval::new(5000, move || {
                tick.set(js_sys::Date::now() as u64)
            });
            move || drop(timer)
        });
    }
    let (unmatched, _, _, unmatched_error, ..) =
        use_collection::<ComponentRef>(props.sbom_id, "/unmatched", true);
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());
    {
        let (counts, error) = (counts.clone(), error.clone());
        use_effect_with((props.sbom_id, token, *tick), move |(id, token, _)| {
            let (id, token) = (*id, token.clone());
            let cancelled = Rc::new(CancelFlag::new(false));
            let pending = cancelled.clone();
            spawn_local(async move {
                let response = api::count_verdicts(vec![id], token.as_deref()).await;
                if pending.get() {
                    return;
                }
                match response {
                    Ok(data) => {
                        error.set(None);
                        counts.set(data.into_iter().next());
                    }
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
    if counts.verdict_freshness.generation.is_none() {
        return html!(<Alert title="Verdicts not computed yet" r#type={AlertType::Info} inline=true>{"Counts will be available after background processing."}</Alert>);
    }
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
        <>
        { freshness_banner(
            &counts.freshness,
            is_refreshing(props.active_job.as_ref(), &counts.freshness),
        ) }
        <Gallery gutter=true>
            { for summary.into_iter().map(|(status, count)| html! {
                <Card><CardBody>{status_label(status)}<Title level={Level::H3}>{count.to_string()}</Title></CardBody></Card>
            }) }
            <Card><CardBody>
                <Label label="No Evidence" color={Color::Grey} />
                if let Some(count) = unmatched.total {
                    <Title level={Level::H3}>{count.to_string()}</Title>
                } else if unmatched_error.is_some() {
                    <p>{"Count unavailable"}</p>
                } else { <Spinner size={SpinnerSize::Md} /> }
            </CardBody></Card>
        </Gallery>
        </>
    }
}
