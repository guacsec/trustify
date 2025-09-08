#[cfg(feature = "garage-door")]
use crate::embedded_oidc;

#[cfg(feature = "graphql")]
use actix_web::middleware;

use crate::{endpoints, profile::spawn_db_check, sample_data};
use actix_web::web;
use anyhow::Context;
use bytesize::ByteSize;
use futures::FutureExt;
use std::{fs::create_dir_all, path::PathBuf, process::ExitCode, sync::Arc};
use tokio_schedule::{Job, every};
use trustify_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    devmode::{FRONTEND_CLIENT_ID, ISSUER_URL},
    swagger_ui::{SwaggerUiOidc, SwaggerUiOidcConfig},
};
use trustify_common::{config::Database, db, model::BinaryByteSize};
use trustify_infrastructure::{
    Infrastructure, InfrastructureConfig, InitContext,
    app::{
        http::{HttpServerBuilder, HttpServerConfig},
        new_auth,
    },
    endpoint::Trustify,
    otel::{Metrics as OtelMetrics, Tracing},
};
use trustify_module_analysis::{config::AnalysisConfig, service::AnalysisService};
use trustify_module_fundamental::purl::service::PurlService;
use trustify_module_ingestor::graph::Graph;
use trustify_module_storage::{
    config::{StorageConfig, StorageStrategy},
    service::{dispatch::DispatchBackend, fs::FileSystemBackend, s3::S3Backend},
};
use trustify_module_ui::{UI, endpoints::UiResources};
use utoipa::openapi::{Info, License};

/// Run the API server
#[derive(clap::Args, Debug)]
pub struct Run {
    #[arg(long, env)]
    pub devmode: bool,

    #[arg(long, env)]
    pub sample_data: bool,

    #[cfg(feature = "graphql")]
    /// Allows enabling the GraphQL endpoint
    #[arg(long, env = "TRUSTD_WITH_GRAPHQL", default_value_t = false)]
    pub with_graphql: bool,

    /// Enable the embedded OIDC server (WARNING: this is insecure and should only be used for demos)
    #[cfg(feature = "garage-door")]
    #[arg(long, env)]
    pub embedded_oidc: bool,

    /// The size limit of SBOMs, uncompressed.
    #[arg(
        long,
        env = "TRUSTD_SBOM_UPLOAD_LIMIT",
        default_value_t = default::sbom_upload_limit()
    )]
    pub sbom_upload_limit: BinaryByteSize,

    /// The size limit of advisories, uncompressed.
    #[arg(
        long,
        env = "TRUSTD_ADVISORY_UPLOAD_LIMIT",
        default_value_t = default::advisory_upload_limit()
    )]
    pub advisory_upload_limit: BinaryByteSize,

    /// The size limit of documents in a dataset, uncompressed.
    #[arg(
        long,
        env = "TRUSTD_DATASET_ENTRY_LIMIT",
        default_value_t = default::dataset_entry_limit()
    )]
    pub dataset_entry_limit: BinaryByteSize,

    /// The size limit of documents for a scan, uncompressed.
    #[arg(
        long,
        env = "TRUSTD_SCAN_LIMIT",
        default_value_t = default::scan_limit()
    )]
    pub scan_limit: BinaryByteSize,

    // flattened commands must go last
    //
    /// Analysis configuration
    #[command(flatten)]
    pub analysis: AnalysisConfig,

    /// Database configuration
    #[command(flatten)]
    pub database: Database,

    /// Location of the storage
    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub http: HttpServerConfig<Trustify>,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[command(flatten)]
    pub ui: UiConfig,
}

mod default {
    use bytesize::ByteSize;
    use trustify_common::model::BinaryByteSize;

    pub const fn sbom_upload_limit() -> BinaryByteSize {
        BinaryByteSize(ByteSize::gib(1))
    }

    pub const fn advisory_upload_limit() -> BinaryByteSize {
        BinaryByteSize(ByteSize::mib(128))
    }

    pub const fn dataset_entry_limit() -> BinaryByteSize {
        BinaryByteSize(ByteSize::gib(1))
    }

    pub const fn scan_limit() -> BinaryByteSize {
        BinaryByteSize(ByteSize::gib(1))
    }
}

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "UI")]
#[group(id = "ui")]
pub struct UiConfig {
    /// Issuer URL used by the UI
    #[arg(id = "ui-issuer-url", long, env = "UI_ISSUER_URL", default_value_t = ISSUER_URL.to_string())]
    pub issuer_url: String,
    /// Client ID used by the UI
    #[arg(id = "ui-client-id", long, env = "UI_CLIENT_ID", default_value_t = FRONTEND_CLIENT_ID.to_string())]
    pub client_id: String,
    /// Scopes to request
    #[arg(id = "ui-scope", long, env = "UI_SCOPE", default_value = "openid")]
    pub scope: String,
}

const SERVICE_ID: &str = "trustify";

struct InitData {
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
    db: db::Database,
    storage: DispatchBackend,
    http: HttpServerConfig<Trustify>,
    tracing: Tracing,
    metrics: OtelMetrics,
    swagger_oidc: Option<Arc<SwaggerUiOidc>>,
    #[cfg(feature = "garage-door")]
    embedded_oidc: Option<embedded_oidc::EmbeddedOidc>,
    ui: UI,
    #[cfg(feature = "graphql")]
    with_graphql: bool,
    config: ModuleConfig,
    analysis: AnalysisService,
}

/// Groups all module configurations.
#[derive(Clone, Default)]
pub(crate) struct ModuleConfig {
    fundamental: trustify_module_fundamental::endpoints::Config,
    ingestor: trustify_module_ingestor::endpoints::Config,
    ui: trustify_module_ui::endpoints::Config,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        // logging is only active once the infrastructure run method has been called
        Infrastructure::from(self.infra.clone())
            .run(
                SERVICE_ID,
                |context| async move { InitData::new(context, self).await },
                |context| async move { context.init_data.run().await },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}

impl InitData {
    async fn new(context: InitContext, run: Run) -> anyhow::Result<Self> {
        // The devmode for the auth parts. This allows us to enable devmode for auth, but not
        // for other parts.
        #[allow(unused_mut)]
        let mut auth_devmode = run.devmode;

        #[cfg(feature = "garage-door")]
        let embedded_oidc = {
            // When running with the embedded OIDC server, re-use devmode. Running the embedded OIDC
            // without devmode doesn't make any sense. However, the pm-mode doesn't know about
            // devmode. Also, enabling devmode might trigger other logic.
            auth_devmode = auth_devmode || run.embedded_oidc;
            embedded_oidc::spawn(run.embedded_oidc).await?
        };

        let (authn, authz) = run.auth.split(auth_devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> =
            Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        let swagger_oidc = match authenticator.is_some() {
            true => SwaggerUiOidc::from_devmode_or_config(auth_devmode, run.swagger_ui_oidc)
                .await?
                .map(Arc::new),
            false => None,
        };

        let db = db::Database::new(&run.database).await?;

        if run.devmode {
            trustify_db::Database(&db).migrate().await?;
        }

        if run.devmode || run.sample_data {
            sample_data(db.clone()).await?;
        }

        context
            .health
            .readiness
            .register("database", spawn_db_check(db.clone())?)
            .await;

        // Schedule any DB garbage collection tasks
        schedule_db_tasks(db.clone());

        let storage = match run.storage.storage_strategy {
            StorageStrategy::Fs => {
                let storage = run
                    .storage
                    .fs_path
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from("./.trustify/storage"));
                if run.devmode {
                    create_dir_all(&storage).context(format!(
                        "Failed to create filesystem storage directory: {:?}",
                        run.storage.fs_path
                    ))?;
                }
                DispatchBackend::Filesystem(
                    FileSystemBackend::new(storage, run.storage.compression).await?,
                )
            }
            StorageStrategy::S3 => DispatchBackend::S3(
                S3Backend::new(run.storage.s3_config, run.storage.compression).await?,
            ),
        };

        let ui = UI {
            version: env!("CARGO_PKG_VERSION").to_string(),
            auth_required: authenticator.is_some().to_string(),
            oidc_server_url: run.ui.issuer_url,
            oidc_client_id: run.ui.client_id,
            oidc_scope: run.ui.scope,
        };

        let config = ModuleConfig {
            fundamental: trustify_module_fundamental::endpoints::Config {
                sbom_upload_limit: run.sbom_upload_limit.into(),
                advisory_upload_limit: run.advisory_upload_limit.into(),
            },
            ingestor: trustify_module_ingestor::endpoints::Config {
                dataset_entry_limit: run.dataset_entry_limit.into(),
            },
            ui: trustify_module_ui::endpoints::Config {
                scan_limit: run.scan_limit.into(),
            },
        };

        Ok(InitData {
            analysis: AnalysisService::new(run.analysis, db.clone()),
            authenticator,
            authorizer,
            db,
            config,
            http: run.http,
            tracing: run.infra.tracing,
            metrics: run.infra.metrics,
            swagger_oidc,
            storage,
            #[cfg(feature = "garage-door")]
            embedded_oidc,
            ui,
            #[cfg(feature = "graphql")]
            with_graphql: run.with_graphql,
        })
    }

    #[allow(unused_mut)]
    async fn run(mut self) -> anyhow::Result<()> {
        let ui = Arc::new(UiResources::new(&self.ui)?);

        let http = {
            HttpServerBuilder::try_from(self.http)?
                .tracing(self.tracing)
                .metrics(self.metrics)
                .authorizer(self.authorizer)
                .swagger_ui_oidc(self.swagger_oidc.clone())
                .openapi_info(default_openapi_info())
                .configure(move |svc| {
                    configure(
                        svc,
                        Config {
                            config: self.config.clone(),
                            db: self.db.clone(),
                            storage: self.storage.clone(),
                            auth: self.authenticator.clone(),
                            analysis: self.analysis.clone(),
                            #[cfg(feature = "graphql")]
                            with_graphql: self.with_graphql,
                        },
                    );
                })
                .post_configure(move |svc| post_configure(svc, PostConfig { ui: ui.clone() }))
        };
        let http = async { http.run().await }.boxed_local();

        #[allow(unused_mut)]
        let mut tasks = vec![http];

        // track the embedded OIDC server task
        #[cfg(feature = "garage-door")]
        if let Some(embedded_oidc) = self.embedded_oidc.take() {
            tasks.push(
                async move {
                    let _ = embedded_oidc.0.await?;
                    Ok::<_, anyhow::Error>(())
                }
                .boxed_local(),
            );
        }

        let (result, _, _) = futures::future::select_all(tasks).await;

        log::info!("one of the server tasks returned, exiting: {result:?}");

        result
    }
}

fn schedule_db_tasks(db: db::Database) {
    let gc_purls = every(5).minutes().perform(move || {
        let db = db.clone();
        let service = PurlService::new();
        async move {
            match service.gc_purls(&db).await {
                Ok(count) => {
                    if count > 0 {
                        log::info!("Garbage collected {count} purls");
                    }
                }
                Err(e) => log::error!("Error collecting purl garbage: {e}"),
            }
        }
    });
    tokio::spawn(gc_purls);
}

pub fn default_openapi_info() -> Info {
    let mut info = Info::new("Trustify", env!("CARGO_PKG_VERSION"));
    info.description = Some("Software Supply-Chain Security API".into());
    info.license = {
        let mut license = License::new("Apache License, Version 2.0");
        license.identifier = Some("Apache-2.0".into());
        Some(license)
    };
    info
}

pub(crate) struct Config {
    pub(crate) config: ModuleConfig,
    pub(crate) db: db::Database,
    pub(crate) storage: DispatchBackend,
    pub(crate) analysis: AnalysisService,
    pub(crate) auth: Option<Arc<Authenticator>>,
    #[cfg(feature = "graphql")]
    pub(crate) with_graphql: bool,
}

pub(crate) fn configure(svc: &mut utoipa_actix_web::service_config::ServiceConfig, config: Config) {
    let Config {
        config:
            ModuleConfig {
                ingestor,
                fundamental,
                ui,
            },
        db,
        storage,
        auth,
        analysis,

        #[cfg(feature = "graphql")]
        with_graphql,
    } = config;

    let graph = Graph::new(db.clone());

    // set global request limits

    let limit = ByteSize::gb(1).as_u64() as usize;
    svc.app_data(web::PayloadConfig::default().limit(limit));

    // register GraphQL API and UI

    #[cfg(feature = "graphql")]
    if with_graphql {
        svc.service(
            utoipa_actix_web::scope("/graphql")
                .map(|svc| {
                    svc.wrap(middleware::NormalizePath::new(
                        middleware::TrailingSlash::Always,
                    ))
                    .wrap(new_auth(auth.clone()))
                })
                .configure(|svc| {
                    trustify_module_graphql::endpoints::configure(svc, db.clone());
                    trustify_module_graphql::endpoints::configure_graphiql(svc);
                }),
        );
    }

    // register REST API & UI

    svc.app_data(graph)
        .configure(|svc| {
            endpoints::configure(svc, auth.clone());
        })
        .service(
            utoipa_actix_web::scope("/api")
                .map(|svc| svc.wrap(new_auth(auth)))
                .configure(|svc| {
                    trustify_module_importer::endpoints::configure(svc, db.clone());
                    trustify_module_ingestor::endpoints::configure(
                        svc,
                        ingestor,
                        db.clone(),
                        storage.clone(),
                        Some(analysis.clone()),
                    );
                    trustify_module_fundamental::endpoints::configure(
                        svc,
                        fundamental,
                        db.clone(),
                        storage,
                        analysis.clone(),
                    );
                    trustify_module_analysis::endpoints::configure(svc, db.clone(), analysis);
                    trustify_module_user::endpoints::configure(svc, db.clone());
                    trustify_module_ui::endpoints::configure(svc, ui)
                }),
        );
}

struct PostConfig {
    ui: Arc<UiResources>,
}

fn post_configure(svc: &mut web::ServiceConfig, config: PostConfig) {
    let PostConfig { ui } = config;

    // register UI

    svc.configure(|svc| {
        // I think the UI must come last due to
        // its use of `resolve_not_found_to`
        trustify_module_ui::endpoints::post_configure(svc, &ui);
    });
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_web::{
        App,
        http::{StatusCode, header},
        test::{TestRequest, call_and_read_body, call_service},
    };
    use clap::{Args, Command, FromArgMatches};
    use std::sync::Arc;
    use test_context::test_context;
    use test_log::test;
    use trustify_infrastructure::app::http::ApplyOpenApi;
    use trustify_module_storage::{
        service::dispatch::DispatchBackend, service::fs::FileSystemBackend,
    };
    use trustify_module_ui::{UI, endpoints::UiResources};
    use trustify_test_context::TrustifyContext;
    use trustify_test_context::app::TestApp;
    use utoipa_actix_web::AppExt;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn initialization(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let context = InitContext::default();
        let run = Run::from_arg_matches(&Run::augment_args(Command::new("cmd")).get_matches_from(
            vec![
                    "cmd",
                    "--db-name",
                    "test",
                    "--db-port",
                    &ctx.postgresql.as_ref().expect("database").settings().port.to_string(),
                ],
        ))?;
        InitData::new(context, run).await.map(|_| ())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(actix_web::test)]
    async fn routing(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let (storage, _) = FileSystemBackend::for_test().await?;
        let ui = Arc::new(UiResources::new(&UI::default())?);
        let analysis = AnalysisService::new(AnalysisConfig::default(), db.clone());
        let app = actix_web::test::init_service(
            App::new()
                .into_utoipa_app()
                .add_test_authorizer()
                .configure(|svc| {
                    configure(
                        svc,
                        Config {
                            config: ModuleConfig::default(),
                            db,
                            storage: DispatchBackend::Filesystem(storage),
                            auth: None,
                            analysis,
                            #[cfg(feature = "graphql")]
                            with_graphql: true,
                        },
                    );
                })
                .apply_openapi(None, None)
                .configure(|svc| post_configure(svc, PostConfig { ui })),
        )
        .await;

        // main UI

        let req = TestRequest::get().uri("/").to_request();
        let body = call_and_read_body(&app, req).await;
        let text = std::str::from_utf8(&body)?;
        assert!(text.contains("<title>Trustification</title>"));

        // redirect

        let req = TestRequest::get().uri("/anything/at/all").to_request();
        let body = call_and_read_body(&app, req).await;
        let text = std::str::from_utf8(&body)?;
        assert!(text.contains("<title>Trustification</title>"));

        // rapidoc UI

        let req = TestRequest::get().uri("/openapi/").to_request();
        let body = call_and_read_body(&app, req).await;
        let text = std::str::from_utf8(&body)?;
        assert!(text.contains("<rapi-doc"));

        // swagger ui

        let req = TestRequest::get().uri("/swagger-ui").to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let loc = resp.headers().get(header::LOCATION);
        assert!(loc.is_some_and(|x| x.eq("/swagger-ui/")));

        let req = TestRequest::get().uri("/swagger-ui/").to_request();
        let body = call_and_read_body(&app, req).await;
        let text = std::str::from_utf8(&body)?;
        assert!(text.contains("<title>Swagger UI</title>"));

        // GraphQL UI
        #[cfg(feature = "graphql")]
        {
            let req = TestRequest::get().uri("/graphql").to_request();
            let body = call_and_read_body(&app, req).await;
            let text = std::str::from_utf8(&body)?;
            assert!(text.contains("<title>GraphiQL IDE</title>"));
        }

        // API

        let req = TestRequest::get().uri("/api").to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::get().uri("/api/v2/advisory").to_request();
        let body = call_and_read_body(&app, req).await;
        let text = std::str::from_utf8(&body)?;
        assert!(text.contains("items"));

        Ok(())
    }
}
