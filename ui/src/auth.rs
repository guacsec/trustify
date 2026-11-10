//! Session recovery and the console's user menu.

use patternfly_yew::prelude::*;
use std::cell::RefCell;
use yew::prelude::*;
use yew_oauth2::{openid, prelude::*};

use crate::AppRoute;

const LOGGED_OUT: &str = "trustify.auth.logged-out";

thread_local! {
    static AUTHENTICATION_FAILED: RefCell<Option<Callback<String>>> = const { RefCell::new(None) };
}

/// Notify the session that a request's bearer token was rejected.
pub fn authentication_failed(token: Option<&str>) {
    if let Some(token) = token {
        let callback = AUTHENTICATION_FAILED.with_borrow(Clone::clone);
        if let Some(callback) = callback {
            callback.emit(token.to_owned());
        }
    }
}

fn is_logged_out() -> bool {
    gloo_utils::window()
        .session_storage()
        .ok()
        .flatten()
        .and_then(|storage| storage.get_item(LOGGED_OUT).ok().flatten())
        .is_some()
}

fn remember_logout(logged_out: bool) {
    let Some(storage) = gloo_utils::window().session_storage().ok().flatten() else {
        return;
    };
    let result = if logged_out {
        storage.set_item(LOGGED_OUT, "true")
    } else {
        storage.remove_item(LOGGED_OUT)
    };
    if let Err(err) = result {
        tracing::debug!("Failed to remember logout: {err:?}");
    }
}

#[derive(Clone, PartialEq)]
struct SessionActions {
    logout: Callback<()>,
}

/// Content protected by the authenticated console session.
#[derive(PartialEq, Properties)]
pub struct SessionProps {
    /// The console shown while authenticated.
    pub children: Html,
}

/// End rejected sessions and offer an explicit login after logout, including after an IdP redirect.
#[function_component(Session)]
pub fn session(props: &SessionProps) -> Html {
    let agent = openid::use_auth_agent();
    let latest_token = use_latest_access_token();
    let logged_out = use_state_eq(is_logged_out);
    let signing_out = use_mut_ref(|| false);

    let logout = use_callback(
        (agent.clone(), logged_out.clone(), signing_out.clone()),
        |(), (agent, logged_out, signing_out)| {
            if signing_out.replace(true) {
                return;
            }
            remember_logout(true);
            logged_out.set(true);
            if let Some(agent) = agent
                && let Err(err) = agent.logout()
            {
                tracing::warn!("Failed to log out: {err}");
            }
        },
    );

    use_effect_with((latest_token, logout.clone()), |(latest_token, logout)| {
        let latest_token = latest_token.clone();
        let logout = logout.clone();
        AUTHENTICATION_FAILED.with_borrow_mut(|handler| {
            *handler = Some(Callback::from(move |rejected: String| {
                // An old request must not end a session whose token was already refreshed.
                if latest_token
                    .as_ref()
                    .and_then(|token| token.access_token())
                    .as_deref()
                    == Some(rejected.as_str())
                {
                    logout.emit(());
                }
            }));
        });
        || AUTHENTICATION_FAILED.with_borrow_mut(|handler| *handler = None)
    });

    let login = use_callback(agent, move |_, agent| {
        if let Some(agent) = agent {
            if let Err(err) = agent.start_login() {
                tracing::warn!("Failed to start login: {err}");
            } else {
                remember_logout(false);
            }
        }
    });

    if *logged_out {
        return html! {
            <Bullseye>
                <EmptyState title="You are logged out" icon={Icon::User}>
                    <Button variant={ButtonVariant::Primary} onclick={login}>{ "Log in" }</Button>
                </EmptyState>
            </Bullseye>
        };
    }

    html! {
        <ContextProvider<SessionActions> context={SessionActions { logout }}>
            <openid::RouterRedirect<AppRoute> logout={AppRoute::SbomList}>
                {props.children.clone()}
            </openid::RouterRedirect<AppRoute>>
        </ContextProvider<SessionActions>>
    }
}

/// User actions in the navbar, shown only for an authenticated session.
#[function_component(UserMenu)]
pub fn user_menu() -> Html {
    let actions = use_context::<SessionActions>();
    let auth = use_auth_state();
    let Some(actions) = actions.filter(|_| {
        auth.as_ref()
            .and_then(OAuth2Context::authentication)
            .is_some()
    }) else {
        return Html::default();
    };

    html! {
        <Toolbar full_height=true>
            <ToolbarContent>
                <ToolbarGroup modifiers={[ToolbarElementModifier::End]}>
                    <ToolbarItem>
                        <Dropdown text={html! { "User" }} icon={html! { {Icon::User} }} aria_label="User menu" position={Position::Right} full_height=true>
                            <MenuAction onclick={actions.logout}>{ "Log out" }</MenuAction>
                        </Dropdown>
                    </ToolbarItem>
                </ToolbarGroup>
            </ToolbarContent>
        </Toolbar>
    }
}
