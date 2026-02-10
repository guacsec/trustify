use anyhow::Context;
use garage_door::{
    issuer::{Client, Issuer, RedirectUrl},
    server::Server,
};
use rand::{RngExt, distr::Alphanumeric};
use tokio::{sync::oneshot, task::JoinHandle};
use trustify_auth::devmode::{
    CONFIDENTIAL_CLIENT_IDS, ISSUER_URL, PUBLIC_CLIENT_IDS, SSO_CLIENT_SECRET,
};
use url::Url;

const SCOPE: &str = "openid read:document create:document delete:document update:document";

pub struct EmbeddedOidc(pub JoinHandle<Result<(), anyhow::Error>>);

fn create(enabled: bool) -> anyhow::Result<Option<Server>> {
    if !enabled {
        log::info!("Embedded OIDC server is not active");
        return Ok(None);
    }

    let mut issuer = Issuer::new(
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect::<String>(),
        [SCOPE],
    )?;

    for id in PUBLIC_CLIENT_IDS {
        issuer = issuer.add_client(Client::Public {
            id: id.to_string(),
            redirect_urls: vec![
                RedirectUrl::Exact {
                    url: "http://localhost".into(),
                    ignore_localhost_port: true,
                },
                RedirectUrl::Exact {
                    url: "http://localhost/openapi/oauth2-redirect.html".into(),
                    ignore_localhost_port: true,
                },
                RedirectUrl::Exact {
                    url: "http://localhost/rapidoc/oauth-receiver.html".into(),
                    ignore_localhost_port: true,
                },
            ],
            default_scope: SCOPE.to_string(),
        });
    }
    for id in CONFIDENTIAL_CLIENT_IDS {
        issuer = issuer.add_client(Client::Confidential {
            id: id.to_string(),
            secret: SSO_CLIENT_SECRET.into(),
            default_scope: SCOPE.to_string(),
        });
    }

    // take the devmode url and extract all information for building the server

    let url = Url::parse(ISSUER_URL)
        .with_context(|| format!("{} Failed to parse URL {}", "EmbeddedOidc", ISSUER_URL))?;
    let port = url.port().unwrap_or(8090);
    let mut path = url
        .path_segments()
        .map(|path| path.collect::<Vec<_>>())
        .unwrap_or_default();
    let name = path.pop().unwrap_or("trustify");
    let base = path.join("/");

    // create the server

    let mut server = Server::new();
    server
        .base(base)
        .port(port)
        .add_issuer(name.to_string(), issuer)?;

    // return

    Ok(Some(server))
}

/// This spawns the embedded OIDC server.
///
/// Awaiting the function ensures that the server was started. Awaiting (the awaited) result of
/// the functions waits for the embedded OIDC server to exit. Which should not happen, but is a
/// sign that something went wrong.
pub async fn spawn(enabled: bool) -> anyhow::Result<Option<EmbeddedOidc>> {
    let Some(mut server) = create(enabled)? else {
        return Ok(None);
    };

    log::warn!(
        "Running embedded OIDC server. This is not secure and should only be used for demos!"
    );

    let (tx, rx) = oneshot::channel::<Url>();

    server.announce_url(|url| {
        log::debug!("Got endpoint announcement: {url}");
        let _ = tx.send(url);
    });

    let handle = tokio::spawn(Box::pin(async move {
        log::info!("Running server loop");
        server.run().await.inspect_err(|err| {
            log::error!("Embedded OIDC server terminated: {err}");
        })?;
        Ok::<(), anyhow::Error>(())
    }));

    let url = rx
        .await
        .context("waiting for embedded OIDC server to start")?;
    log::info!("Embedded OIDC server ready on: {url}");

    // done

    Ok(Some(EmbeddedOidc(handle)))
}
