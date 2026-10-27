//! Static UI registration, independent of supporting API endpoints.

use crate::profile::api::UiConfig;
use actix_web::web::ServiceConfig;
#[cfg(all(feature = "trustify-ui", feature = "ui-console"))]
use actix_web::{HttpResponse, web};
#[cfg(feature = "ui-console")]
use actix_web_static_files::{ResourceFiles, deps::static_files::Resource};
#[cfg(feature = "ui-console")]
use std::collections::HashMap;
#[cfg(any(feature = "trustify-ui", feature = "ui-console"))]
use std::sync::Arc;
#[cfg(feature = "ui-console")]
use trustify_correlation_ui::{Mount, resources};
#[cfg(feature = "trustify-ui")]
use trustify_module_ui::{UI, endpoints::UiResources};

/// Resources prepared once and shared between HTTP workers.
#[derive(Clone)]
pub(crate) struct EmbeddedUis {
    #[cfg(feature = "trustify-ui")]
    trustify: Arc<UiResources>,
    #[cfg(feature = "ui-console")]
    console: Arc<HashMap<&'static str, Resource>>,
}

#[cfg(feature = "ui-console")]
const CONSOLE_MOUNT: Mount = if cfg!(feature = "trustify-ui") {
    Mount::Console
} else {
    Mount::Root
};

impl EmbeddedUis {
    /// Prepare enabled UIs using the shared frontend authentication settings.
    pub(crate) fn new(_config: &UiConfig, _auth_required: bool) -> anyhow::Result<Self> {
        Ok(Self {
            #[cfg(feature = "trustify-ui")]
            trustify: Arc::new(UiResources::new(&UI {
                version: env!("CARGO_PKG_VERSION").to_string(),
                auth_required: _auth_required.to_string(),
                oidc_server_url: _config.issuer_url.clone(),
                oidc_client_id: _config.client_id.clone(),
                oidc_scope: _config.scope.clone(),
                oidc_load_user: _config.load_user.to_string(),
            })?),
            #[cfg(feature = "ui-console")]
            console: Arc::new(resources(CONSOLE_MOUNT)),
        })
    }

    /// Register after backend routes, with prefixed UI routes before the root fallback.
    pub(crate) fn configure(&self, _svc: &mut ServiceConfig) {
        #[cfg(all(feature = "trustify-ui", feature = "ui-console"))]
        _svc.route(
            "/console",
            web::get().to(|| async {
                HttpResponse::PermanentRedirect()
                    .append_header(("Location", "/console/"))
                    .finish()
            }),
        );
        #[cfg(feature = "ui-console")]
        _svc.service(
            ResourceFiles::new(
                CONSOLE_MOUNT.path().trim_end_matches('/'),
                self.console.clone(),
            )
            .resolve_not_found_to_root(),
        );
        #[cfg(feature = "trustify-ui")]
        trustify_module_ui::endpoints::post_configure(_svc, &self.trustify);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_web::{
        App, HttpResponse,
        http::StatusCode,
        test::{TestRequest, call_service, init_service, read_body},
        web,
    };
    #[cfg(feature = "ui-console")]
    use regex::Regex;
    use std::str::from_utf8;
    #[cfg(feature = "ui-console")]
    use url::Url;

    #[actix_web::test]
    async fn mounts_and_backend_precedence() -> anyhow::Result<()> {
        let ui = EmbeddedUis::new(&UiConfig::default(), false)?;
        let app = init_service(
            App::new()
                .route(
                    "/api/probe",
                    web::get().to(|| async { HttpResponse::NoContent().finish() }),
                )
                .configure(|svc| ui.configure(svc)),
        )
        .await;
        let response = call_service(&app, TestRequest::get().uri("/api/probe").to_request()).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        for path in ["/", "/anything/at/all"] {
            let response = call_service(&app, TestRequest::get().uri(path).to_request()).await;
            if cfg!(any(feature = "trustify-ui", feature = "ui-console")) {
                assert_eq!(response.status(), StatusCode::OK, "{path}");
                let body = read_body(response).await;
                let html = from_utf8(&body)?;
                let title = if cfg!(feature = "trustify-ui") {
                    "<title>Trustification</title>"
                } else {
                    "<title>Trustify Console</title>"
                };
                assert!(html.contains(title), "{path}: {title}");
            } else {
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }
        }

        #[cfg(feature = "ui-console")]
        {
            if cfg!(feature = "trustify-ui") {
                let response =
                    call_service(&app, TestRequest::get().uri("/console").to_request()).await;
                assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
                assert_eq!(response.headers().get("Location").unwrap(), "/console/");
            }
            for tail in ["", "advisory/some-id"] {
                let path = format!("{}{tail}", CONSOLE_MOUNT.path());
                let response = call_service(&app, TestRequest::get().uri(&path).to_request()).await;
                assert_eq!(response.status(), StatusCode::OK);
                let body = read_body(response).await;
                let html = from_utf8(&body)?;
                assert!(
                    html.contains("<title>Trustify Console</title>"),
                    "expected console at {path}, received {}",
                    html.chars().take(200).collect::<String>()
                );
                assert!(html.contains(&format!("<base href=\"{}\"", CONSOLE_MOUNT.path())));
            }
            let console = resources(CONSOLE_MOUNT);
            let css_urls = Regex::new(r#"url\(\s*[\"']?([^\"')\s]+)"#)?;
            let base = Url::parse("http://localhost")?.join(CONSOLE_MOUNT.path())?;
            for (name, resource) in &console {
                let name = *name;
                if name == "index.html" {
                    continue;
                }
                let path = format!("{}{name}", CONSOLE_MOUNT.path());
                let response = call_service(&app, TestRequest::get().uri(&path).to_request()).await;
                assert_eq!(response.status(), StatusCode::OK, "{path}");
                assert_eq!(
                    response.headers().get("Content-Type").unwrap(),
                    resource.mime_type,
                    "{path}"
                );
                assert_eq!(read_body(response).await.as_ref(), resource.data, "{path}");
                if resource.mime_type == "text/css" {
                    let stylesheet = base.join(name)?;
                    let css = from_utf8(resource.data)?;
                    // Inline source maps contain original SCSS, not browser asset URLs.
                    let css = css
                        .split("/*# sourceMappingURL=")
                        .next()
                        .unwrap_or_default();
                    for capture in css_urls.captures_iter(css) {
                        let reference = &capture[1];
                        if reference.starts_with("data:") || reference.starts_with('#') {
                            continue;
                        }
                        let asset = stylesheet.join(reference)?;
                        if asset.origin() != base.origin() {
                            continue;
                        }
                        let key = asset
                            .path()
                            .strip_prefix(CONSOLE_MOUNT.path())
                            .expect("stylesheet assets must stay within the console mount");
                        assert!(console.contains_key(key), "missing CSS asset: {asset}");
                    }
                }
            }
        }
        Ok(())
    }
}
