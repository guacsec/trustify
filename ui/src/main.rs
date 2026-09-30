mod advisory;
mod api;
mod correlation;
mod ingest;
mod model;
mod query;
mod sbom_list;

use advisory::AdvisoryPage;
use browser_panic_hook::{CustomBody, IntoPanicHook};
use correlation::CorrelationView;
use ingest::IngestPage;
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
    Advisory {
        id: String,
    },
    Query,
    Ingest,
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
            let redirect_url = gloo_utils::window().location().origin().expect("origin");
            let login_options = LoginOptions::new()
                .with_redirect_url(Url::parse(&redirect_url).expect("redirect url"))
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
            <ToastViewer>
                <RouterSwitch<AppRoute> render={switch_route} />
            </ToastViewer>
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
            <Nav>
                <NavList>
                    <NavRouterItem<AppRoute> to={AppRoute::SbomList}>
                        { "SBOMs" }
                    </NavRouterItem<AppRoute>>
                    <NavRouterItem<AppRoute> to={AppRoute::Query}>
                        { "Query" }
                    </NavRouterItem<AppRoute>>
                    <NavRouterItem<AppRoute> to={AppRoute::Ingest}>
                        { "Ingest" }
                    </NavRouterItem<AppRoute>>
                </NavList>
            </Nav>
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
