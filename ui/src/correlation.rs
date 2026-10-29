//! SBOM correlation view layout and collection tabs.
use crate::{AppRoute, api, model::SbomSummary};
use patternfly_yew::prelude::*;
use std::{cell::Cell as CancelFlag, rc::Rc};
use trustify_api::correlation::RefreshJob;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

mod common;
mod pagination;
pub(crate) mod processing;
mod summary;
mod unmatched;
mod verdicts;

pub(crate) use common::{confidence_label, matched_value, status_color, timestamp};
use summary::CorrelationSummary;
use unmatched::UnmatchedTable;
use verdicts::VerdictTable;

/// Properties of the SBOM correlation view.
#[derive(Clone, Debug, PartialEq, Properties)]
pub struct CorrelationViewProps {
    pub sbom_id: String,
}

/// Show an SBOM's metadata and independently paginated correlation collections.
#[function_component(CorrelationView)]
pub fn correlation_view(props: &CorrelationViewProps) -> Html {
    let result = use_state(|| Option::<SbomSummary>::None);
    let loading = use_state(|| true);
    let error = use_state(|| Option::<String>::None);
    let active_job = use_state(|| Option::<RefreshJob>::None);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let sbom_id = props.sbom_id.clone();
        let result = result.clone();
        let loading = loading.clone();
        let error = error.clone();
        let active_job = active_job.clone();
        let token = token.clone();
        use_effect_with((sbom_id.clone(), token.clone()), move |(id, token)| {
            let id = id.clone();
            let token = token.clone();
            let cancelled = Rc::new(CancelFlag::new(false));
            let header_pending = cancelled.clone();
            {
                let token = token.clone();
                let pending = cancelled.clone();
                spawn_local(async move {
                    // Only refines the freshness alert; ignore failures and superseded requests.
                    let job = api::fetch_freshness(token.as_deref())
                        .await
                        .ok()
                        .and_then(|overview| overview.active_job);
                    if !pending.get() {
                        active_job.set(job);
                    }
                });
            }
            spawn_local(async move {
                loading.set(true);
                error.set(None);
                let response = api::fetch_sbom(&id, token.as_deref()).await;
                if header_pending.get() {
                    return;
                }
                match response {
                    Ok(data) => result.set(Some(data)),
                    Err(e) => error.set(Some(e.to_string())),
                }
                loading.set(false);
            });
            move || cancelled.set(true)
        });
    }

    let sbom_name = match &*result {
        Some(sbom) => sbom.name.as_str(),
        _ => props.sbom_id.as_str(),
    };

    html! {
        <PageSection>
            <Breadcrumb>
                <BreadcrumbRouterItem<AppRoute> to={AppRoute::SbomList}>
                    { "SBOMs" }
                </BreadcrumbRouterItem<AppRoute>>
                <BreadcrumbItem>
                    { sbom_name }
                </BreadcrumbItem>
                <BreadcrumbItem>
                    { "Correlation" }
                </BreadcrumbItem>
            </Breadcrumb>

            if *loading {
                <Bullseye>
                    <Spinner />
                </Bullseye>
            } else if let Some(err) = &*error {
                <Alert title="Failed to load correlation" r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
            } else if let Some(data) = &*result {
                if let Ok(sbom_id) = uuid::Uuid::parse_str(&data.id) {
                    <CorrelationContent key={sbom_id.to_string()} {sbom_id} active_job={(*active_job).clone()} />
                }
            } else {
                <EmptyState
                    title="No data"
                    icon={Icon::Cubes}
                    size={Size::XXXXLarge}
                >
                    { "No correlation result available." }
                </EmptyState>
            }
        </PageSection>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct CorrelationContentProps {
    sbom_id: uuid::Uuid,
    #[prop_or_default]
    active_job: Option<RefreshJob>,
}

#[function_component(CorrelationContent)]
fn correlation_content(props: &CorrelationContentProps) -> Html {
    html! {
        <>
            <CorrelationSummary sbom_id={props.sbom_id} active_job={props.active_job.clone()} />
            <br />
                        <VerdictTable sbom_id={props.sbom_id} />
                        <br />
                        <UnmatchedTable sbom_id={props.sbom_id} />

        </>
    }
}
