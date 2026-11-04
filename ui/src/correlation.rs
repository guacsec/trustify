//! SBOM correlation view layout and collection tabs.
use crate::{AppRoute, api, model::SbomSummary};
use patternfly_yew::prelude::*;
use std::{cell::Cell as CancelFlag, rc::Rc};
use trustify_api::correlation::VerdictFreshness;
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
use processing::SbomStatus;
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

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let sbom_id = props.sbom_id.clone();
        let result = result.clone();
        let loading = loading.clone();
        let error = error.clone();
        let token = token.clone();
        use_effect_with((sbom_id.clone(), token.clone()), move |(id, token)| {
            let id = id.clone();
            let token = token.clone();
            let cancelled = Rc::new(CancelFlag::new(false));
            let header_pending = cancelled.clone();
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
                    <CorrelationContent key={sbom_id.to_string()} {sbom_id} />
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
struct CorrelationPageProps {
    sbom_id: uuid::Uuid,
}

/// Properties of the sections of the correlation view.
#[derive(Clone, Debug, PartialEq, Properties)]
struct CorrelationContentProps {
    sbom_id: uuid::Uuid,
    /// Incremented to reload all sections, e.g. once newer verdicts are available.
    #[prop_or_default]
    reload: u64,
    /// Receives the verdict freshness of the loaded verdicts.
    #[prop_or_default]
    onfreshness: Callback<Option<VerdictFreshness>>,
}

/// The status of the SBOM's results, above the sections showing them.
#[function_component(CorrelationContent)]
fn correlation_content(props: &CorrelationPageProps) -> Html {
    let reload = use_state_eq(|| 0_u64);
    let shown = use_state_eq(|| None::<VerdictFreshness>);
    let onfreshness = {
        let shown = shown.clone();
        Callback::from(move |freshness| shown.set(freshness))
    };
    let onreload = {
        let reload = reload.clone();
        Callback::from(move |()| reload.set(*reload + 1))
    };
    let sbom_id = props.sbom_id;
    html! {
        <>
            <SbomStatus {sbom_id} shown={(*shown).clone()} {onreload} />
            <CorrelationSummary {sbom_id} reload={*reload} />
            <br />
            <VerdictTable {sbom_id} reload={*reload} {onfreshness} />
            <br />
            <UnmatchedTable {sbom_id} reload={*reload} />
        </>
    }
}
