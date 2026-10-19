mod advisory;
mod advisory_list;
mod api;
mod correlation;
mod ingest;
mod ingest_drop;
mod model;
mod monaco;
mod options;
mod provider_alias;
mod query;
mod resolution;
mod sbom_list;
mod sort;

use advisory::AdvisoryPage;
use advisory_list::AdvisoryList;
use browser_panic_hook::{CustomBody, IntoPanicHook};
use correlation::CorrelationView;
use ingest::IngestPage;
use ingest_drop::{IngestDropZone, IngestionProvider};
use options::OptionsPage;
use patternfly_yew::prelude::*;
use query::QueryPage;
use sbom_list::SbomList;
use trustify_api::FrontendOidcInfo;
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use yew::{Renderer, prelude::*, set_custom_panic_hook};
use yew_nested_router::{
    Target,
    prelude::{Switch as RouterSwitch, *},
};
use yew_oauth2::{components::redirect::router::openid::RouterRedirect, openid, prelude::*};

#[derive(Debug, Default, Clone, PartialEq, Eq, Target)]
pub enum AppRoute {
    #[default]
    #[target(index)]
    SbomList,
    Correlation {
        id: String,
    },
    AdvisoryList,
    Advisory {
        id: String,
    },
    Query,
    Ingest,
    Options,
    ProviderAliases,
}

pub fn main() -> Result<(), JsValue> {
    let log_level = if cfg!(debug_assertions) {
        log::Level::Trace
    } else {
        log::Level::Info
    };
    wasm_logger::init(wasm_logger::Config::new(log_level));
    set_custom_panic_hook(
        CustomBody(Box::new(|details| {
            format!(
                r#"
<div class="pf-v6-l-bullseye">
  <div class="pf-v6-l-bullseye__item">
    <div class="pf-v6-c-alert pf-m-danger" aria-label="Application panicked">
      <div class="pf-v6-c-alert__icon">
        <i class="fas fa-fw fa-exclamation-circle" aria-hidden="true"></i>
      </div>
      <p class="pf-v6-c-alert__title">Application panicked</p>
      <div class="pf-v6-c-alert__description">
        <pre>{message}</pre>
      </div>
    </div>
  </div>
</div>
"#,
                message = details.message()
            )
        }))
        .into_panic_hook(),
    );
    Renderer::<Application>::new().render();
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
enum DiscoveryState {
    Loading,
    Ready(Option<FrontendOidcInfo>),
    Failed(String),
}

#[function_component(Application)]
fn app() -> Html {
    let state = use_state(|| DiscoveryState::Loading);

    {
        let state = state.clone();
        use_effect_with((), move |()| {
            spawn_local(async move {
                match api::fetch_well_known().await {
                    Ok(info) => state.set(DiscoveryState::Ready(info.frontend.oidc)),
                    Err(e) => state.set(DiscoveryState::Failed(e.to_string())),
                }
            });
        });
    }

    match &*state {
        DiscoveryState::Loading => html! {
            <Bullseye>
                <Spinner />
            </Bullseye>
        },
        DiscoveryState::Failed(err) => html! {
            <Bullseye>
                <Alert title="Failed to connect" r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
            </Bullseye>
        },
        DiscoveryState::Ready(Some(oidc)) => {
            let config = openid::Config::new(&oidc.client_id, &oidc.issuer_url);
            let scopes = oidc
                .scope
                .split_whitespace()
                .map(String::from)
                .collect::<Vec<_>>();
            let redirect_url = match redirect_url() {
                Ok(url) => url,
                Err(err) => {
                    return html! {
                        <Bullseye>
                            <Alert title="Failed to configure login" r#type={AlertType::Danger} inline=true>
                                <p>{ err }</p>
                            </Alert>
                        </Bullseye>
                    };
                }
            };
            let login_options = LoginOptions::new()
                .with_redirect_url(redirect_url)
                .with_nested_router_redirect();
            html! {
                <Router<AppRoute> default={AppRoute::SbomList}>
                    <openid::OAuth2 {config} {scopes} login_options={login_options}>
                        <Failure>
                            <AuthError />
                        </Failure>
                        <RouterRedirect<AppRoute> logout={AppRoute::SbomList}>
                            <AppShell />
                        </RouterRedirect<AppRoute>>
                    </openid::OAuth2>
                </Router<AppRoute>>
            }
        }
        DiscoveryState::Ready(None) => html! {
            <Router<AppRoute> default={AppRoute::SbomList}>
                <AppShell />
            </Router<AppRoute>>
        },
    }
}

/// The URL the OIDC provider redirects back to: the app's origin.
fn redirect_url() -> Result<Url, String> {
    let origin = gloo_utils::window()
        .location()
        .origin()
        .map_err(|err| format!("failed to get origin: {err:?}"))?;
    Url::parse(&origin).map_err(|err| format!("invalid redirect URL '{origin}': {err}"))
}

#[function_component(AuthError)]
fn auth_error() -> Html {
    html! {
        <Bullseye>
            <Alert title="Authentication failed" r#type={AlertType::Danger} inline=true>
                <FailureMessage />
            </Alert>
        </Bullseye>
    }
}

#[function_component(AppShell)]
fn app_shell() -> Html {
    html! {
        <BackdropViewer>
            <IngestionProvider>
                <RouterSwitch<AppRoute> render={switch_route} />
            </IngestionProvider>
        </BackdropViewer>
    }
}

fn switch_route(target: AppRoute) -> Html {
    match target {
        AppRoute::SbomList => html! {
            <AppPage>
                <SbomList />
            </AppPage>
        },
        AppRoute::Correlation { id } => html! {
            <AppPage>
                <CorrelationView sbom_id={id} />
            </AppPage>
        },
        AppRoute::AdvisoryList => html! {
            <AppPage>
                <AdvisoryList />
            </AppPage>
        },
        AppRoute::Advisory { id } => html! {
            <AppPage>
                <AdvisoryPage advisory_id={id} />
            </AppPage>
        },
        AppRoute::Query => html! {
            <AppPage>
                <QueryPage />
            </AppPage>
        },
        AppRoute::Ingest => html! {
            <AppPage>
                <IngestPage />
            </AppPage>
        },
        AppRoute::ProviderAliases => html! {
            <AppPage>
                <provider_alias::ProviderAliasPage />
            </AppPage>
        },
        AppRoute::Options => html! {
            <AppPage>
                <OptionsPage />
            </AppPage>
        },
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct PageProps {
    pub children: Children,
}

#[function_component(AppPage)]
fn page(props: &PageProps) -> Html {
    let sidebar = html_nested! {
        <PageSidebar>
            <div class="trustify-sidebar-content">
                <Nav>
                    <NavList>
                        <NavRouterItem<AppRoute> to={AppRoute::SbomList}>
                            { "SBOMs" }
                        </NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::AdvisoryList}>
                            { "Advisories" }
                        </NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::Query}>
                            { "Query" }
                        </NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::Ingest}>
                            { "Ingest" }
                        </NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::ProviderAliases}>
                            { "Provider aliases" }
                        </NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::Options}>
                            { "Options" }
                        </NavRouterItem<AppRoute>>
                    </NavList>
                </Nav>
                <IngestDropZone />
            </div>
        </PageSidebar>
    };

    let brand = html! {
        <MastheadBrand>
            <Title level={Level::H4}>
                { "Trustify Correlation" }
            </Title>
        </MastheadBrand>
    };

    html! {
        <Page {brand} {sidebar}>
            { for props.children.iter() }
        </Page>
    }
}
