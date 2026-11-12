use crate::{
    app::{AppOptions, SecurityHeaders, new_app},
    endpoint::Endpoint,
    otel::{Metrics, Tracing},
};
use actix_cors::Cors;
use actix_tls::{accept::openssl::reexports::SslAcceptor, connect::openssl::reexports::SslMethod};
use actix_web::{
    App, HttpServer,
    dev::{ServiceFactory, ServiceRequest},
    web::{self, JsonConfig},
};
use anyhow::{Context, anyhow};
use bytesize::ByteSize;
use clap::{Arg, ArgMatches, Args, Command, Error, FromArgMatches, value_parser};
use openssl::{
    error::ErrorStack,
    ssl::{SslFiletype, SslOptions, SslVersion},
};
use opentelemetry_instrumentation_actix_web::{RequestMetrics, RequestTracing, RouteFormatter};
use std::{
    fmt::{self, Debug},
    marker::PhantomData,
    net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener},
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};
use trustify_auth::{
    authenticator::Authenticator,
    authorizer::Authorizer,
    swagger_ui::{SwaggerUiOidc, swagger_ui_with_auth},
};
use trustify_common::model::BinaryByteSize;
use utoipa::openapi::Info;
use utoipa_actix_web::AppExt;

const DEFAULT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);

#[derive(Debug, Clone)]
pub struct DefaultRootRouteFormatter;

impl RouteFormatter for DefaultRootRouteFormatter {
    fn format(&self, path: &str) -> String {
        if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        }
    }
}

#[derive(Clone, Debug)]
pub struct BindPort<E: Endpoint> {
    /// The port to listen on
    pub bind_port: u16,

    _marker: Marker<E>,
}

impl<E: Endpoint> Deref for BindPort<E> {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.bind_port
    }
}

impl<E: Endpoint> Default for BindPort<E> {
    fn default() -> Self {
        Self {
            bind_port: E::PORT,
            _marker: Default::default(),
        }
    }
}

impl<E: Endpoint> Args for BindPort<E> {
    fn augment_args(cmd: Command) -> Command {
        Self::augment_args_for_update(cmd)
    }

    fn augment_args_for_update(cmd: Command) -> Command {
        cmd.arg(
            Arg::new("http-server-bind-port")
                .short('p')
                .long("http-server-bind-port")
                .help("The port to listen on")
                .value_parser(value_parser!(u16))
                .default_value(E::PORT.to_string()),
        )
    }
}

impl<E: Endpoint> FromArgMatches for BindPort<E> {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
        Ok(Self {
            bind_port: matches
                .get_one::<u16>("http-server-bind-port")
                .cloned()
                .unwrap_or(E::port()),
            _marker: Default::default(),
        })
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), Error> {
        if let Some(port) = matches.get_one::<u16>("port") {
            self.bind_port = *port;
        }
        Ok(())
    }
}

/// TLS security profile, aligned with OpenShift TLS Security Profiles.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Default)]
pub enum TlsSecurityProfile {
    /// TLS 1.0+, broadest compatibility.
    #[clap(name = "old")]
    Old,
    /// TLS 1.2+, broad compatibility.
    #[clap(name = "intermediate")]
    Intermediate,
    /// TLS 1.3 only, most secure.
    #[default]
    #[clap(name = "modern")]
    Modern,
    /// User-defined min TLS version and cipher suites.
    #[clap(name = "custom")]
    Custom,
}

impl fmt::Display for TlsSecurityProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsSecurityProfile::Old => write!(f, "old"),
            TlsSecurityProfile::Intermediate => write!(f, "intermediate"),
            TlsSecurityProfile::Modern => write!(f, "modern"),
            TlsSecurityProfile::Custom => write!(f, "custom"),
        }
    }
}

/// Minimum TLS protocol version.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum TlsMinVersion {
    #[clap(name = "1.0")]
    Tls1_0,
    #[clap(name = "1.1")]
    Tls1_1,
    #[clap(name = "1.2")]
    Tls1_2,
    #[clap(name = "1.3")]
    Tls1_3,
}

impl fmt::Display for TlsMinVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsMinVersion::Tls1_0 => write!(f, "1.0"),
            TlsMinVersion::Tls1_1 => write!(f, "1.1"),
            TlsMinVersion::Tls1_2 => write!(f, "1.2"),
            TlsMinVersion::Tls1_3 => write!(f, "1.3"),
        }
    }
}

impl TlsMinVersion {
    fn to_ssl_version(self) -> SslVersion {
        match self {
            TlsMinVersion::Tls1_0 => SslVersion::TLS1,
            TlsMinVersion::Tls1_1 => SslVersion::TLS1_1,
            TlsMinVersion::Tls1_2 => SslVersion::TLS1_2,
            TlsMinVersion::Tls1_3 => SslVersion::TLS1_3,
        }
    }
}

#[derive(Clone, Debug, clap::Args)]
#[command(
    rename_all_env = "SCREAMING_SNAKE_CASE",
    next_help_heading = "HTTP endpoint"
)]
#[group(id = "http")]
pub struct HttpServerConfig<E>
where
    E: Endpoint + Send + Sync,
{
    /// The number of worker threads, defaults to zero, which falls back to the number of cores.
    #[arg(
        id = "http-server-workers",
        long,
        env = "HTTP_SERVER_WORKERS",
        default_value_t = 0
    )]
    pub workers: usize,

    /// The address to listen on
    #[arg(
        id = "http-server-bind-address",
        long,
        env = "HTTP_SERVER_BIND_ADDR",
        default_value_t = default::bind_addr(),
    )]
    pub bind_addr: String,

    // This is required due to: https://github.com/clap-rs/clap/issues/5127
    #[command(flatten)]
    pub bind_port: BindPort<E>,

    /// The overall request limit
    #[arg(
        id = "http-server-request-limit",
        long,
        env = "HTTP_SERVER_REQUEST_LIMIT",
        default_value_t = default::request_limit(),
    )]
    pub request_limit: BinaryByteSize,

    /// The JSON request limit
    #[arg(
        id = "http-server-json-limit",
        long,
        env = "HTTP_SERVER_JSON_LIMIT",
        default_value_t = default::json_limit(),
    )]
    pub json_limit: BinaryByteSize,

    /// Enable TLS
    #[arg(
        id = "http-server-tls-enabled",
        long,
        env = "HTTP_SERVER_TLS_ENABLED",
        default_value_t = false,
        action = clap::ArgAction::Set
    )]
    pub tls_enabled: bool,

    /// The path to the TLS key file in PEM format
    #[arg(
        id = "http-server-tls-key-file",
        long,
        env = "HTTP_SERVER_TLS_KEY_FILE"
    )]
    pub tls_key_file: Option<PathBuf>,

    /// The path to the TLS certificate in PEM format
    #[arg(
        id = "http-server-tls-certificate-file",
        long,
        env = "HTTP_SERVER_TLS_CERTIFICATE_FILE"
    )]
    pub tls_certificate_file: Option<PathBuf>,

    /// TLS security profile (old, intermediate, modern, custom)
    #[arg(
        id = "http-server-tls-security-profile",
        long,
        env = "HTTP_SERVER_TLS_SECURITY_PROFILE",
        default_value_t = TlsSecurityProfile::Modern,
    )]
    pub tls_security_profile: TlsSecurityProfile,

    /// Minimum TLS version (only used with custom profile)
    #[arg(
        id = "http-server-tls-min-version",
        long,
        env = "HTTP_SERVER_TLS_MIN_VERSION"
    )]
    pub tls_min_version: Option<TlsMinVersion>,

    /// TLS 1.2 cipher list in OpenSSL format (only used with custom profile)
    #[arg(id = "http-server-tls-ciphers", long, env = "HTTP_SERVER_TLS_CIPHERS")]
    pub tls_ciphers: Option<String>,

    /// TLS 1.3 ciphersuites in OpenSSL format (only used with custom profile)
    #[arg(
        id = "http-server-tls-ciphersuites",
        long,
        env = "HTTP_SERVER_TLS_CIPHERSUITES"
    )]
    pub tls_ciphersuites: Option<String>,

    /// Key-exchange groups in OpenSSL format, in preference order, separated by
    /// `:` (for example `X25519MLKEM768:X25519:secp256r1`).
    ///
    /// Unlike the cipher settings this applies to every profile, because the
    /// groups are orthogonal to the cipher suites: the hybrid post-quantum key
    /// exchange `X25519MLKEM768` is a group, not a cipher. Leaving it unset
    /// keeps OpenSSL's own default list, which on OpenSSL 3.5 and later already
    /// offers `X25519MLKEM768` first.
    #[arg(id = "http-server-tls-groups", long, env = "HTTP_SERVER_TLS_GROUPS")]
    pub tls_groups: Option<String>,

    /// Disable the request log
    #[arg(id = "http-disable-log", long, env = "HTTP_SERVER_DISABLE_LOG")]
    pub disable_log: bool,

    /// Allowed CORS origins. Repeat the flag or provide a comma-separated list.
    /// When empty (the default), cross-origin requests are rejected (same-origin
    /// only). The bundled UI is served same-origin and does not require CORS.
    #[arg(
        id = "http-server-cors-allowed-origins",
        long,
        env = "HTTP_SERVER_CORS_ALLOWED_ORIGINS",
        value_delimiter = ','
    )]
    pub cors_allowed_origins: Vec<String>,

    /// Allow ANY origin (development only). This reflects the request origin and
    /// permits any method/header. Do not use in production; prefer
    /// --http-server-cors-allowed-origins.
    #[arg(
        id = "http-server-cors-permissive",
        long,
        env = "HTTP_SERVER_CORS_PERMISSIVE",
        default_value_t = false
    )]
    pub cors_permissive: bool,

    /// Disable the defense-in-depth security response headers
    /// (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP, HSTS).
    #[arg(
        id = "http-server-security-headers-disabled",
        long,
        env = "HTTP_SERVER_SECURITY_HEADERS_DISABLED",
        default_value_t = false
    )]
    pub security_headers_disabled: bool,

    /// The Content-Security-Policy header value. An empty value omits the
    /// header. A full XSS-mitigating policy is deployment-specific because
    /// `connect-src` must include the OIDC issuer used by the UI.
    #[arg(
        id = "http-server-csp",
        long,
        env = "HTTP_SERVER_CSP",
        default_value = default::CSP
    )]
    pub csp: String,

    /// The Strict-Transport-Security header value. An empty value omits the
    /// header. Only honored by browsers over HTTPS.
    #[arg(
        id = "http-server-hsts",
        long,
        env = "HTTP_SERVER_HSTS",
        default_value = default::HSTS
    )]
    pub hsts: String,

    #[arg(skip)]
    _marker: Marker<E>,
}

mod default {
    use super::*;

    /// Non-breaking default: restrict framing (clickjacking defense) without
    /// constraining content sources, which would require the deployment's OIDC
    /// issuer in `connect-src`. Operators should tighten this per deployment.
    pub const CSP: &str = "frame-ancestors 'none'";

    pub const HSTS: &str = "";

    pub fn bind_addr() -> String {
        "::1".to_string()
    }

    pub const fn request_limit() -> BinaryByteSize {
        BinaryByteSize(ByteSize::kib(256))
    }

    pub const fn json_limit() -> BinaryByteSize {
        BinaryByteSize(ByteSize::mib(2))
    }
}

impl<E: Endpoint> Default for HttpServerConfig<E>
where
    E: Endpoint + Send + Sync,
{
    fn default() -> Self {
        Self {
            workers: 0,
            bind_addr: default::bind_addr(),
            bind_port: BindPort::<E>::default(),
            request_limit: default::request_limit(),
            json_limit: default::json_limit(),
            tls_enabled: false,
            tls_key_file: None,
            tls_certificate_file: None,
            tls_security_profile: TlsSecurityProfile::Modern,
            tls_min_version: None,
            tls_ciphers: None,
            tls_ciphersuites: None,
            tls_groups: None,
            disable_log: false,
            cors_allowed_origins: Vec::new(),
            cors_permissive: false,
            security_headers_disabled: false,
            csp: default::CSP.to_string(),
            hsts: default::HSTS.to_string(),
            _marker: Default::default(),
        }
    }
}

#[derive(Debug)]
struct Marker<E>(PhantomData<E>);

impl<E> Default for Marker<E> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<E> Clone for Marker<E> {
    fn clone(&self) -> Self {
        Default::default()
    }
}

impl<E> TryFrom<HttpServerConfig<E>> for HttpServerBuilder
where
    E: Endpoint + Send + Sync,
{
    type Error = anyhow::Error;

    fn try_from(value: HttpServerConfig<E>) -> Result<Self, Self::Error> {
        let addr = SocketAddr::new(
            IpAddr::from_str(&value.bind_addr).context("parse bind address")?,
            value.bind_port.bind_port,
        );

        let mut result = HttpServerBuilder::new()
            .workers(value.workers)
            .bind(addr)
            .request_limit(value.request_limit.0.0 as _)
            .json_limit(value.json_limit.0.0 as _);

        result = match (value.cors_permissive, value.cors_allowed_origins.as_slice()) {
            (true, _) => {
                log::warn!(
                    "CORS is permissive (any origin allowed). Do not use this in production!"
                );
                result.cors(Cors::permissive)
            }
            (false, []) => result.cors_disabled(),
            (false, origins) => {
                let origins = origins.to_vec();
                result.cors(move || {
                    let mut cors = Cors::default()
                        .allow_any_header()
                        .allow_any_method()
                        .supports_credentials()
                        .max_age(3600);
                    for origin in &origins {
                        cors = cors.allowed_origin(origin);
                    }
                    cors
                })
            }
        };

        result = result.security_headers(if value.security_headers_disabled {
            None
        } else {
            Some(SecurityHeaders {
                content_security_policy: value.csp,
                // HSTS must never be advertised by a plain HTTP listener, and
                // remains opt-in even when TLS is configured.
                strict_transport_security: if value.tls_enabled {
                    value.hsts
                } else {
                    String::new()
                },
            })
        });

        if value.tls_enabled {
            if value.tls_security_profile == TlsSecurityProfile::Custom
                && value.tls_min_version.is_none()
            {
                return Err(anyhow!(
                    "Custom TLS profile requires --http-server-tls-min-version"
                ));
            }
            result = result.tls(TlsConfiguration {
                key: value.tls_key_file.ok_or_else(|| {
                    anyhow!("TLS enabled but no key file configured (use --http-server-tls-key-file)")
                })?,
                certificate: value.tls_certificate_file.ok_or_else(|| {
                    anyhow!("TLS enabled but no certificate file configured (use --http-server-tls-certificate-file)")
                })?,
                security_profile: value.tls_security_profile,
                min_version: value.tls_min_version,
                ciphers: optional_list(value.tls_ciphers),
                ciphersuites: optional_list(value.tls_ciphersuites),
                groups: optional_list(value.tls_groups),
            });
        }

        Ok(result)
    }
}

/// Normalise one of the optional OpenSSL list settings (ciphers, ciphersuites,
/// key-exchange groups) into "configured" or "not configured".
///
/// An environment variable that is *set but empty* arrives here as `Some("")`,
/// which is not the same thing as unset — and an empty list is never what the
/// operator meant. Passed straight through to OpenSSL the three behave
/// differently, and two of them fail quietly:
///
///  * `SSL_CTX_set1_groups_list("")` succeeds and installs an empty group
///    list. The server starts, and then every TLS 1.3 handshake fails with
///    "handshake failure" because no key-exchange group is on offer.
///  * `SSL_CTX_set_ciphersuites("")` succeeds and disables every TLS 1.3
///    cipher suite, with the same result on a TLS 1.3 listener.
///  * `SSL_CTX_set_cipher_list("")` is the only one that errors, so that one
///    at least fails loudly at startup.
///
/// Treating empty and whitespace-only as unset means a blank value falls back
/// to the system or OpenSSL default, which is the sane reading of "I did not
/// configure this". Surrounding whitespace is trimmed from real values too:
/// OpenSSL treats spaces as list separators, so a stray leading space would
/// otherwise be parsed as an empty element.
fn optional_list(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub type ConfiguratorFn =
    dyn Fn(&mut utoipa_actix_web::service_config::ServiceConfig) + Send + Sync;

pub type PostConfiguratorFn = dyn Fn(&mut web::ServiceConfig) + Send + Sync;

pub struct HttpServerBuilder {
    configurator: Option<Arc<ConfiguratorFn>>,
    post_configurator: Option<Arc<PostConfiguratorFn>>,

    bind: Bind,
    tls: Option<TlsConfiguration>,

    cors_factory: Option<Arc<dyn Fn() -> Cors + Send + Sync>>,
    security_headers: Option<SecurityHeaders>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Option<Authorizer>,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,

    workers: usize,
    json_limit: Option<usize>,
    request_limit: Option<usize>,
    tracing: Tracing,
    metrics: Metrics,

    disable_log: bool,

    openapi_info: Option<Info>,
}

pub struct TlsConfiguration {
    certificate: PathBuf,
    key: PathBuf,
    security_profile: TlsSecurityProfile,
    min_version: Option<TlsMinVersion>,
    ciphers: Option<String>,
    ciphersuites: Option<String>,
    groups: Option<String>,
}

/// Cipher list for protocol versions below TLS 1.2, mirroring the cipher list
/// of OpenShift's `Old` TLS security profile (`configv1.TLSProfiles[Old]`,
/// itself Mozilla's "old" configuration).
///
/// `mozilla_intermediate_v5` configures AEAD suites only -- GCM and
/// ChaCha20-Poly1305 -- and those are defined for TLS 1.2 and above. TLS 1.0
/// and 1.1 can only negotiate CBC suites, so a profile that permits the older
/// protocols but keeps the intermediate cipher list has nothing to offer a
/// legacy client and the handshake fails on cipher negotiation.
///
/// The AEAD suites are kept, and first: a profile that allows TLS 1.0 still
/// serves modern clients over TLS 1.2+, and should prefer the strong suites
/// when it can. The CBC suites are the fallback that makes the older protocols
/// actually usable. Keeping a SECLEVEL-acceptable suite at the head also means
/// `set_cipher_list` still succeeds on hosts whose OpenSSL configuration
/// filters the weak tail out entirely.
const LEGACY_CIPHER_LIST: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
     ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
     ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
     ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
     ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:\
     ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:\
     ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:\
     AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:\
     AES128-SHA:AES256-SHA";

/// Permit TLS 1.0 and 1.1 on a builder derived from `mozilla_intermediate_v5`.
///
/// Two things stand in the way, and clearing only the first is what made this
/// subtly broken before:
///
///  1. The protocol vetoes. `mozilla_intermediate_v5` disables TLS 1.0 and 1.1
///     through `SslOptions`, not only through the minimum protocol version, so
///     lowering the minimum alone has no effect.
///  2. The cipher list. See [`LEGACY_CIPHER_LIST`] -- the inherited list is
///     AEAD-only and cannot be negotiated below TLS 1.2.
///
/// An explicit cipher list from the caller takes precedence and is applied
/// afterwards, so this only supplies the default.
///
/// Note that the host's OpenSSL configuration can still refuse: a
/// `TLS.MinProtocol` setting or a security level of 2 or above (the default
/// under RHEL's and Fedora's crypto-policies) prohibits TLS below 1.2
/// regardless of what the application asks for. That is deliberately left
/// alone -- overriding a system-wide cryptographic policy is the
/// administrator's decision, not this server's.
fn allow_legacy_protocols(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
) -> Result<(), ErrorStack> {
    builder.clear_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
    builder.set_cipher_list(LEGACY_CIPHER_LIST)
}

/// Build an SSL acceptor configured according to the given TLS profile.
fn build_ssl_acceptor(tls: &TlsConfiguration) -> anyhow::Result<openssl::ssl::SslAcceptorBuilder> {
    let mut acceptor = match tls.security_profile {
        TlsSecurityProfile::Old => {
            let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
                .context("creating Old TLS profile acceptor")?;
            builder
                .set_min_proto_version(None)
                .context("clearing min TLS version for Old profile")?;
            allow_legacy_protocols(&mut builder)
                .context("configuring legacy protocols for Old profile")?;
            builder
        }
        TlsSecurityProfile::Intermediate => {
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
                .context("creating Intermediate TLS profile acceptor")?
        }
        TlsSecurityProfile::Modern => SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())
            .context("creating Modern TLS profile acceptor")?,
        TlsSecurityProfile::Custom => {
            let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
                .context("creating Custom TLS profile acceptor")?;
            if let Some(min_version) = tls.min_version {
                if matches!(min_version, TlsMinVersion::Tls1_0 | TlsMinVersion::Tls1_1) {
                    // Supplies the legacy cipher default; an explicit
                    // tls.ciphers below overrides it.
                    allow_legacy_protocols(&mut builder)
                        .context("configuring legacy protocols for Custom profile")?;
                }
                builder
                    .set_min_proto_version(Some(min_version.to_ssl_version()))
                    .context("setting custom min TLS version")?;
            }
            if let Some(ref ciphers) = tls.ciphers {
                builder
                    .set_cipher_list(ciphers)
                    .context("setting custom TLS 1.2 cipher list")?;
            }
            if let Some(ref ciphersuites) = tls.ciphersuites {
                builder
                    .set_ciphersuites(ciphersuites)
                    .context("setting custom TLS 1.3 ciphersuites")?;
            }
            builder
        }
    };

    // Applied to every profile: the key-exchange groups are independent of the
    // cipher suites, and the hybrid post-quantum exchange is selected here
    // rather than through a cipher. An unknown group name makes OpenSSL reject
    // the whole list, so this fails loudly instead of silently serving a
    // different key exchange than the one that was asked for.
    if let Some(ref groups) = tls.groups {
        acceptor
            .set_groups_list(groups)
            .with_context(|| format!("setting TLS key-exchange groups ({groups})"))?;
    }

    Ok(acceptor)
}

pub enum Bind {
    /// Use the provided listener
    Listener(TcpListener),
    /// Bind to the provided address and port
    Address(SocketAddr),
}

impl Default for HttpServerBuilder {
    fn default() -> Self {
        HttpServerBuilder::new()
    }
}

impl HttpServerBuilder {
    pub fn new() -> Self {
        Self {
            configurator: None,
            post_configurator: None,
            bind: Bind::Address(DEFAULT_ADDR),
            tls: None,
            cors_factory: None,
            security_headers: None,
            authenticator: None,
            authorizer: None,
            swagger_ui_oidc: None,
            workers: 0,
            json_limit: None,
            request_limit: None,
            tracing: Tracing::default(),
            metrics: Metrics::default(),
            openapi_info: None,
            disable_log: false,
        }
    }

    /// Set a custom CORS factory.
    ///
    /// The default is no CORS (same-origin only). Use this to opt into
    /// cross-origin access for explicitly trusted origins.
    pub fn cors<F>(mut self, cors_factory: F) -> Self
    where
        F: Fn() -> Cors + Send + Sync + 'static,
    {
        self.cors_factory = Some(Arc::new(cors_factory));
        self
    }

    pub fn cors_disabled(mut self) -> Self {
        self.cors_factory = None;
        self
    }

    /// Set the security response headers applied to every response.
    pub fn security_headers(mut self, security_headers: Option<SecurityHeaders>) -> Self {
        self.security_headers = security_headers;
        self
    }

    pub fn default_authenticator(mut self, authenticator: Option<Arc<Authenticator>>) -> Self {
        self.authenticator = authenticator;
        self
    }

    pub fn authorizer(mut self, authorizer: Authorizer) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    pub fn swagger_ui_oidc(mut self, swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>) -> Self {
        self.swagger_ui_oidc = swagger_ui_oidc;
        self
    }

    pub fn tracing(mut self, tracing: Tracing) -> Self {
        self.tracing = tracing;
        self
    }

    pub fn metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn openapi_info(mut self, openapi_info: Info) -> Self {
        self.openapi_info = Some(openapi_info);
        self
    }

    pub fn configure<F>(mut self, configurator: F) -> Self
    where
        F: Fn(&mut utoipa_actix_web::service_config::ServiceConfig) + Send + Sync + 'static,
    {
        self.configurator = Some(Arc::new(configurator));
        self
    }

    pub fn post_configure<F>(mut self, post_configurator: F) -> Self
    where
        F: Fn(&mut web::ServiceConfig) + Send + Sync + 'static,
    {
        self.post_configurator = Some(Arc::new(post_configurator));
        self
    }

    pub fn listen(mut self, listener: TcpListener) -> Self {
        self.bind = Bind::Listener(listener);
        self
    }

    pub fn bind(mut self, addr: impl Into<SocketAddr>) -> Self {
        self.bind = Bind::Address(addr.into());
        self
    }

    pub fn tls(mut self, tls: impl Into<Option<TlsConfiguration>>) -> Self {
        self.tls = tls.into();
        self
    }

    pub fn workers(mut self, workers: usize) -> Self {
        self.workers = workers;
        self
    }

    pub fn json_limit(mut self, json_limit: usize) -> Self {
        self.json_limit = Some(json_limit);
        self
    }

    pub fn request_limit(mut self, request_limit: usize) -> Self {
        self.request_limit = Some(request_limit);
        self
    }

    pub fn disable_log(mut self, disable_log: bool) -> Self {
        self.disable_log = disable_log;
        self
    }

    pub async fn run(self) -> anyhow::Result<()> {
        if let Some(limit) = self.request_limit {
            log::info!("JSON limit: {}", BinaryByteSize::from(limit));
        }
        if let Some(limit) = self.json_limit {
            log::info!("Payload limit: {}", BinaryByteSize::from(limit));
        }

        let mut http = HttpServer::new(move || {
            let cors = self.cors_factory.as_ref().map(|factory| factory());

            let mut json = JsonConfig::default();
            if let Some(limit) = self.json_limit {
                json = json.limit(limit);
            }

            let (logger, tracing_logger) = match (self.disable_log, self.tracing) {
                (true, Tracing::Disabled) => (None, None),
                (false, Tracing::Disabled) => {
                    (Some(actix_web::middleware::Logger::default()), None)
                }
                (_, Tracing::Enabled) => (None, Some(RequestTracing::default())),
            };

            log::debug!(
                "Loggers ({}) - logger: {}, tracing: {}",
                self.tracing,
                logger.is_some(),
                tracing_logger.is_some()
            );

            let metrics = match self.metrics {
                Metrics::Disabled => None,
                Metrics::Enabled => {
                    let request_metrics = RequestMetrics::builder()
                        .with_route_formatter(DefaultRootRouteFormatter)
                        .build();
                    Some(request_metrics)
                }
            };

            log::debug!(
                "OTELMetrics({}) - metrics: {}",
                self.metrics,
                metrics.is_some()
            );

            let mut app = new_app(AppOptions {
                cors,
                authenticator: self.authenticator.clone(),
                authorizer: self
                    .authorizer
                    .clone()
                    .unwrap_or_else(|| Authorizer::new(None)),
                logger,
                tracing_logger,
                metrics,
                security_headers: self.security_headers.clone(),
            })
            .app_data(json)
            .into_utoipa_app();

            // configure payload limit

            if let Some(limit) = self.request_limit {
                app = app.app_data(web::PayloadConfig::new(limit));
            }

            // configure application

            let app = app.configure(|svc| {
                if let Some(config) = &self.configurator {
                    config(svc);
                }
            });

            let app = app.apply_openapi(self.openapi_info.clone(), self.swagger_ui_oidc.clone());

            // apply post-configuration, required mostly for "catch call" handlers

            app.configure(|svc| {
                if let Some(post_config) = &self.post_configurator {
                    post_config(svc);
                }
            })
        });

        http = http.tcp_nodelay(true);

        if self.workers > 0 {
            log::info!("Using {} worker(s)", self.workers);
            http = http.workers(self.workers);
        }

        let tls = match self.tls {
            Some(tls) => {
                log::info!("Enabling TLS support (profile: {})", tls.security_profile);
                let mut acceptor = build_ssl_acceptor(&tls)?;
                acceptor
                    .set_certificate_chain_file(tls.certificate)
                    .context("setting certificate chain")?;
                acceptor
                    .set_private_key_file(tls.key, SslFiletype::PEM)
                    .context("setting private key")?;
                Some(acceptor)
            }
            None => None,
        };

        match self.bind {
            Bind::Listener(listener) => {
                log::info!("Binding to provided listener: {listener:?}");
                http = match tls {
                    Some(tls) => http
                        .listen_openssl(listener, tls)
                        .context("listen with TLS")?,
                    None => http.listen(listener).context("listen")?,
                };
            }
            Bind::Address(addr) => {
                log::info!("Binding to: {addr}");
                http = match tls {
                    Some(tls) => http.bind_openssl(addr, tls).context("bind with TLS")?,
                    None => http.bind(addr).context("bind")?,
                };
            }
        }

        Ok(http.run().await?)
    }
}

pub trait ApplyOpenApi<T> {
    /// Turn a [`UtoipaApp`] into a [`App`] by applying the API spec
    fn apply_openapi(
        self,
        openapi_info: Option<Info>,
        swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
    ) -> App<T>;
}

impl<T> ApplyOpenApi<T> for utoipa_actix_web::UtoipaApp<T>
where
    T: ServiceFactory<ServiceRequest, Config = (), Error = actix_web::Error, InitError = ()>,
{
    fn apply_openapi(
        self,
        openapi_info: Option<Info>,
        swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
    ) -> App<T> {
        let (app, mut openapi) = self.split_for_parts();
        if let Some(info) = openapi_info {
            openapi.info = info;
        }

        // register OpenAPI UIs

        app.service(swagger_ui_with_auth(openapi, swagger_ui_oidc))
            .service(web::redirect("/openapi", "/swagger-ui/"))
            .service(web::redirect("/openapi/", "/swagger-ui/"))
            .service(web::redirect("/swagger-ui", "/swagger-ui/"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug)]
    pub struct MockEndpoint;

    impl Endpoint for MockEndpoint {
        const PORT: u16 = 1234;
        const PATH: &'static str = "";
    }

    #[test]
    fn default_config_converts() {
        HttpServerBuilder::try_from(HttpServerConfig::<MockEndpoint>::default()).unwrap();
    }

    /// Verifies that the default config uses the Modern TLS profile.
    #[test]
    fn default_tls_profile_is_modern() {
        let config = HttpServerConfig::<MockEndpoint>::default();
        assert_eq!(config.tls_security_profile, TlsSecurityProfile::Modern);
    }

    /// Verifies that a Custom profile without min_version is rejected.
    #[test]
    fn custom_profile_requires_min_version() {
        let config = HttpServerConfig::<MockEndpoint> {
            tls_enabled: true,
            tls_key_file: Some(PathBuf::from("/tmp/key.pem")),
            tls_certificate_file: Some(PathBuf::from("/tmp/cert.pem")),
            tls_security_profile: TlsSecurityProfile::Custom,
            tls_min_version: None,
            ..Default::default()
        };
        let err = match HttpServerBuilder::try_from(config) {
            Err(e) => e,
            Ok(_) => panic!("expected error for Custom profile without min_version"),
        };
        assert!(
            err.to_string().contains("--http-server-tls-min-version"),
            "error should mention --http-server-tls-min-version, got: {err}"
        );
    }

    /// Verifies that all named profiles are accepted during config conversion.
    #[test]
    fn all_profiles_accepted() {
        for profile in [
            TlsSecurityProfile::Old,
            TlsSecurityProfile::Intermediate,
            TlsSecurityProfile::Modern,
        ] {
            let config = HttpServerConfig::<MockEndpoint> {
                tls_enabled: true,
                tls_key_file: Some(PathBuf::from("/tmp/key.pem")),
                tls_certificate_file: Some(PathBuf::from("/tmp/cert.pem")),
                tls_security_profile: profile,
                ..Default::default()
            };
            HttpServerBuilder::try_from(config).unwrap();
        }
    }

    /// Verifies the default config is fail-closed: no CORS (same-origin only).
    #[test]
    fn default_cors_is_fail_closed() {
        let config = HttpServerConfig::<MockEndpoint>::default();
        assert!(config.cors_allowed_origins.is_empty());
        assert!(!config.cors_permissive);
        let builder = HttpServerBuilder::try_from(config).unwrap();
        assert!(
            builder.cors_factory.is_none(),
            "default CORS factory must be None (same-origin only)"
        );
    }

    /// Verifies explicit allowed origins produce a CORS factory.
    #[test]
    fn explicit_cors_origins_enable_cors() {
        let config = HttpServerConfig::<MockEndpoint> {
            cors_allowed_origins: vec!["https://ui.example.com".to_string()],
            ..Default::default()
        };
        let builder = HttpServerBuilder::try_from(config).unwrap();
        assert!(builder.cors_factory.is_some());
    }

    /// Verifies the permissive opt-in produces a CORS factory.
    #[test]
    fn permissive_cors_opt_in() {
        let config = HttpServerConfig::<MockEndpoint> {
            cors_permissive: true,
            ..Default::default()
        };
        let builder = HttpServerBuilder::try_from(config).unwrap();
        assert!(builder.cors_factory.is_some());
    }

    /// Verifies security headers are enabled by default with sane values.
    #[test]
    fn default_security_headers_enabled() {
        let config = HttpServerConfig::<MockEndpoint>::default();
        assert!(!config.security_headers_disabled);
        assert_eq!(config.csp, default::CSP);
        assert_eq!(config.hsts, default::HSTS);
        let builder = HttpServerBuilder::try_from(config).unwrap();
        let headers = builder.security_headers.expect("security headers enabled");
        assert!(headers.strict_transport_security.is_empty());
    }

    /// Verifies that HSTS is opt-in and only applied to TLS listeners.
    #[test]
    fn hsts_is_enabled_for_tls_only() {
        let config = HttpServerConfig::<MockEndpoint> {
            tls_enabled: true,
            tls_key_file: Some(PathBuf::from("/tmp/key.pem")),
            tls_certificate_file: Some(PathBuf::from("/tmp/cert.pem")),
            hsts: "max-age=31536000; includeSubDomains".to_string(),
            ..Default::default()
        };
        let builder = HttpServerBuilder::try_from(config).unwrap();
        let headers = builder.security_headers.expect("security headers enabled");
        assert_eq!(
            headers.strict_transport_security,
            "max-age=31536000; includeSubDomains"
        );
    }

    /// Verifies security headers can be disabled via config.
    #[test]
    fn security_headers_can_be_disabled() {
        let config = HttpServerConfig::<MockEndpoint> {
            security_headers_disabled: true,
            ..Default::default()
        };
        let builder = HttpServerBuilder::try_from(config).unwrap();
        assert!(builder.security_headers.is_none());
    }

    /// Verifies that Custom profile with min_version is accepted.
    #[test]
    fn custom_profile_with_min_version_accepted() {
        let config = HttpServerConfig::<MockEndpoint> {
            tls_enabled: true,
            tls_key_file: Some(PathBuf::from("/tmp/key.pem")),
            tls_certificate_file: Some(PathBuf::from("/tmp/cert.pem")),
            tls_security_profile: TlsSecurityProfile::Custom,
            tls_min_version: Some(TlsMinVersion::Tls1_2),
            ..Default::default()
        };
        HttpServerBuilder::try_from(config).unwrap();
    }

    fn tls_config(profile: TlsSecurityProfile) -> TlsConfiguration {
        TlsConfiguration {
            certificate: PathBuf::from("/tmp/cert.pem"),
            key: PathBuf::from("/tmp/key.pem"),
            security_profile: profile,
            min_version: None,
            ciphers: None,
            ciphersuites: None,
            groups: None,
        }
    }

    /// The `Old` profile is built from Mozilla's *intermediate* configuration,
    /// which vetoes TLS 1.0 and 1.1 through `SslOptions` as well as through the
    /// minimum protocol version. Clearing the minimum version alone leaves
    /// those options in place, so the profile would reject exactly the legacy
    /// clients it exists to serve.
    #[test]
    fn old_profile_really_allows_legacy_protocols() {
        let mut acceptor = build_ssl_acceptor(&tls_config(TlsSecurityProfile::Old)).unwrap();

        assert_eq!(
            acceptor.min_proto_version(),
            None,
            "the Old profile must not pin a minimum protocol version"
        );
        let options = acceptor.options();
        assert!(
            !options.contains(SslOptions::NO_TLSV1) && !options.contains(SslOptions::NO_TLSV1_1),
            "the Old profile still vetoes TLS 1.0/1.1 through SslOptions: {options:?}"
        );
    }

    /// The same trap, reached the other way: a Custom profile that explicitly
    /// asks for a minimum of TLS 1.0.
    #[test]
    fn custom_profile_honors_a_legacy_min_version() {
        let mut tls = tls_config(TlsSecurityProfile::Custom);
        tls.min_version = Some(TlsMinVersion::Tls1_0);

        let mut acceptor = build_ssl_acceptor(&tls).unwrap();

        assert_eq!(acceptor.min_proto_version(), Some(SslVersion::TLS1));
        let options = acceptor.options();
        assert!(
            !options.contains(SslOptions::NO_TLSV1) && !options.contains(SslOptions::NO_TLSV1_1),
            "a minimum of TLS 1.0 is vetoed by SslOptions: {options:?}"
        );
    }

    /// A Custom profile that stays at TLS 1.2 must keep the veto: clearing it
    /// unconditionally would quietly re-enable TLS 1.0 for everyone.
    #[test]
    fn custom_profile_keeps_the_veto_above_tls_1_1() {
        let mut tls = tls_config(TlsSecurityProfile::Custom);
        tls.min_version = Some(TlsMinVersion::Tls1_2);

        let acceptor = build_ssl_acceptor(&tls).unwrap();

        let options = acceptor.options();
        assert!(
            options.contains(SslOptions::NO_TLSV1) && options.contains(SslOptions::NO_TLSV1_1),
            "TLS 1.0/1.1 must stay disabled for a TLS 1.2 minimum: {options:?}"
        );
    }

    /// Key-exchange groups apply to every profile, not just Custom: they are
    /// orthogonal to the cipher suites, and the cluster TLS profile can name
    /// them independently of everything else.
    #[test]
    fn groups_apply_to_every_profile() {
        for profile in [
            TlsSecurityProfile::Old,
            TlsSecurityProfile::Intermediate,
            TlsSecurityProfile::Modern,
            TlsSecurityProfile::Custom,
        ] {
            let mut tls = tls_config(profile);
            tls.groups = Some("X25519:secp256r1".to_string());
            build_ssl_acceptor(&tls)
                .unwrap_or_else(|e| panic!("groups rejected for {profile} profile: {e}"));
        }
    }

    /// An unknown group name must fail loudly. OpenSSL rejects the whole list
    /// when one entry is unknown, so accepting the error here is what stops the
    /// server from silently negotiating a different key exchange than the one
    /// it was configured with.
    #[test]
    fn unknown_group_is_rejected() {
        let mut tls = tls_config(TlsSecurityProfile::Modern);
        tls.groups = Some("X25519:NotARealGroup".to_string());

        let err = match build_ssl_acceptor(&tls) {
            Err(e) => e,
            Ok(_) => panic!("an unknown group must be rejected"),
        };
        assert!(
            err.to_string().contains("NotARealGroup"),
            "the error should name the group list, got: {err}"
        );
    }

    /// The hybrid post-quantum group is what PQC in TLS 1.3 actually is -- a
    /// key-exchange group, not a cipher suite. It needs OpenSSL 3.5 or later,
    /// which is what the RHEL 10 based images ship; older build hosts skip.
    #[test]
    fn pqc_group_is_accepted() {
        const OPENSSL_3_5_0: i64 = 0x3050_0000;
        if openssl::version::number() < OPENSSL_3_5_0 {
            eprintln!(
                "skipping: X25519MLKEM768 needs OpenSSL >= 3.5, found {}",
                openssl::version::version()
            );
            return;
        }

        let mut tls = tls_config(TlsSecurityProfile::Modern);
        tls.groups = Some("X25519MLKEM768:X25519".to_string());
        build_ssl_acceptor(&tls).expect("X25519MLKEM768 should be accepted on OpenSSL >= 3.5");
    }

    /// No groups configured means OpenSSL's own default list, which is what
    /// every deployment that does not opt in keeps getting.
    #[test]
    fn no_groups_configured_is_accepted() {
        build_ssl_acceptor(&tls_config(TlsSecurityProfile::Modern)).unwrap();
    }

    /// A self-signed certificate, so the handshake tests have something to
    /// serve. Verification is disabled on the client side, so the contents
    /// beyond the key do not matter.
    fn self_signed() -> (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ) {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let key = openssl::pkey::PKey::from_rsa(rsa).unwrap();

        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();

        let mut cert = openssl::x509::X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();

        (cert.build(), key)
    }

    /// Run one real handshake against an acceptor built from `tls`, with a
    /// client pinned to `client_max`, and report the negotiated protocol
    /// version.
    ///
    /// Both ends have their security level lowered to 0. That is a *test*
    /// measure, not something the server does: the host's OpenSSL
    /// configuration (RHEL and Fedora crypto-policies set `@SECLEVEL=2` and
    /// `TLS.MinProtocol = TLSv1.2`) otherwise rejects TLS 1.0 on version
    /// grounds before a cipher is ever chosen, which would mask exactly the
    /// cipher-negotiation behaviour these tests exist to pin.
    fn handshake(tls: &TlsConfiguration, client_max: SslVersion) -> Result<String, String> {
        handshake_with(tls, client_max, "ALL:@SECLEVEL=0")
    }

    fn handshake_with(
        tls: &TlsConfiguration,
        client_max: SslVersion,
        client_ciphers: &str,
    ) -> Result<String, String> {
        use openssl::ssl::{Ssl, SslConnector, SslVerifyMode};
        use std::io::{Read, Write};

        let (cert, key) = self_signed();
        let mut builder = build_ssl_acceptor(tls).map_err(|e| format!("build: {e}"))?;
        builder.set_security_level(0);
        builder.set_certificate(&cert).unwrap();
        builder.set_private_key(&key).unwrap();
        let acceptor = builder.build();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || match listener.accept() {
            Ok((sock, _)) => match acceptor.accept(sock) {
                Ok(mut stream) => {
                    let version = stream.ssl().version_str().to_string();
                    let _ = stream.write_all(b"ok");
                    Ok(version)
                }
                Err(e) => Err(format!("server: {e}")),
            },
            Err(e) => Err(format!("accept: {e}")),
        });

        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_security_level(0);
        connector.set_verify(SslVerifyMode::NONE);
        connector
            .set_min_proto_version(Some(SslVersion::TLS1))
            .unwrap();
        connector.set_max_proto_version(Some(client_max)).unwrap();
        connector.set_cipher_list(client_ciphers).unwrap();
        let context = connector.build().into_context();

        let sock = std::net::TcpStream::connect(addr).unwrap();
        let mut ssl = Ssl::new(&context).unwrap();
        ssl.set_verify(SslVerifyMode::NONE);
        let client = match openssl::ssl::SslStream::new(ssl, sock) {
            Ok(mut stream) => match std::io::Write::flush(&mut stream).and_then(|()| {
                openssl::ssl::SslStream::connect(&mut stream)
                    .map_err(std::io::Error::other)
                    .map(|()| stream)
            }) {
                Ok(mut stream) => {
                    let mut buf = [0u8; 2];
                    let _ = stream.read(&mut buf);
                    Ok(())
                }
                Err(e) => Err(format!("client: {e}")),
            },
            Err(e) => Err(format!("client setup: {e}")),
        };

        let served = server.join().unwrap();
        client.and(served)
    }

    /// Cipher list for a legacy client in these tests.
    ///
    /// RSA key transport, deliberately: below TLS 1.2 an ECDHE suite signs its
    /// ServerKeyExchange with MD5+SHA1, and OpenSSL under RHEL's and Fedora's
    /// crypto-policies refuses to produce a SHA1 signature at all ("invalid
    /// digest"), at any security level. RSA key transport needs no such
    /// signature, so it is the part of the legacy cipher list that can
    /// actually be exercised here. A deployment that genuinely needs ECDHE
    /// over TLS 1.0 needs a host crypto policy that permits SHA1 signatures --
    /// nothing the server can configure.
    const LEGACY_CLIENT_CIPHERS: &str = "AES128-SHA:AES256-SHA";

    /// The regression this exists for: the `Old` profile permitted TLS 1.0 and
    /// 1.1 at the protocol level but inherited `mozilla_intermediate_v5`'s
    /// AEAD-only cipher list. AEAD suites are TLS 1.2 and above, so a legacy
    /// client got all the way to cipher negotiation and then failed with
    /// "handshake failure" -- the profile was old in name only.
    #[test]
    fn old_profile_completes_a_legacy_handshake() {
        let tls = tls_config(TlsSecurityProfile::Old);

        for (version, client_max) in [("TLSv1", SslVersion::TLS1), ("TLSv1.1", SslVersion::TLS1_1)]
        {
            match handshake_with(&tls, client_max, LEGACY_CLIENT_CIPHERS) {
                Ok(negotiated) => assert_eq!(
                    negotiated, version,
                    "the Old profile should negotiate {version}"
                ),
                Err(e) => panic!("the Old profile could not serve a {version} client: {e}"),
            }
        }
    }

    /// Permitting the old protocols must not cost the modern ones: the AEAD
    /// suites stay at the head of the list, so a current client still gets
    /// TLS 1.3.
    #[test]
    fn old_profile_still_serves_modern_clients() {
        let negotiated = handshake(&tls_config(TlsSecurityProfile::Old), SslVersion::TLS1_3)
            .expect("the Old profile should still serve a modern client");
        assert_eq!(negotiated, "TLSv1.3");
    }

    /// The same trap by the other route: a Custom profile asking for a TLS 1.0
    /// minimum without naming its own ciphers.
    #[test]
    fn custom_profile_with_legacy_min_completes_a_handshake() {
        let mut tls = tls_config(TlsSecurityProfile::Custom);
        tls.min_version = Some(TlsMinVersion::Tls1_0);

        let negotiated = handshake_with(&tls, SslVersion::TLS1, LEGACY_CLIENT_CIPHERS)
            .expect("a Custom profile with a TLS 1.0 minimum should serve a TLS 1.0 client");
        assert_eq!(negotiated, "TLSv1");
    }

    /// An explicit cipher list still wins: the legacy default is only a
    /// default. Here the caller names AEAD-only suites alongside a TLS 1.0
    /// minimum, so TLS 1.0 becomes unnegotiable again -- their choice, and the
    /// server must honor it rather than quietly widening the list.
    #[test]
    fn explicit_ciphers_override_the_legacy_default() {
        let mut tls = tls_config(TlsSecurityProfile::Custom);
        tls.min_version = Some(TlsMinVersion::Tls1_0);
        tls.ciphers = Some("ECDHE-RSA-AES128-GCM-SHA256".to_string());

        let err = handshake_with(&tls, SslVersion::TLS1, LEGACY_CLIENT_CIPHERS)
            .expect_err("an AEAD-only cipher list cannot negotiate TLS 1.0");
        assert!(
            err.contains("handshake failure") || err.contains("no shared cipher"),
            "want a cipher negotiation failure, got: {err}"
        );
    }

    /// A profile that does not ask for the old protocols keeps the inherited
    /// AEAD cipher list, so the legacy default cannot leak into Intermediate
    /// or Modern.
    #[test]
    fn modern_profile_rejects_a_legacy_client() {
        let err = handshake(&tls_config(TlsSecurityProfile::Modern), SslVersion::TLS1)
            .expect_err("the Modern profile must not serve a TLS 1.0 client");
        assert!(
            err.contains("protocol version") || err.contains("handshake failure"),
            "want a version or cipher rejection, got: {err}"
        );
    }

    /// Unit-level view of the normaliser, including the values that only a
    /// shell or a ConfigMap produces.
    #[test]
    fn optional_list_treats_blank_as_unset() {
        assert_eq!(optional_list(None), None);
        assert_eq!(optional_list(Some(String::new())), None);
        assert_eq!(optional_list(Some("   ".to_string())), None);
        assert_eq!(optional_list(Some("\t\n ".to_string())), None);
        // Real values survive, with surrounding whitespace trimmed: OpenSSL
        // treats a space as a list separator, so a stray one would be read as
        // an empty element.
        assert_eq!(
            optional_list(Some("  X25519MLKEM768:X25519 ".to_string())),
            Some("X25519MLKEM768:X25519".to_string())
        );
    }

    /// `HTTP_SERVER_TLS_GROUPS=` (set, but empty) must not reach OpenSSL.
    ///
    /// This is the quiet one: `set_groups_list("")` *succeeds*, so the server
    /// starts normally and then fails every TLS 1.3 handshake because it
    /// offers no key-exchange group. A startup error would have been kinder.
    #[test]
    fn empty_groups_fall_back_to_the_default() {
        let mut tls = tls_config(TlsSecurityProfile::Modern);
        tls.groups = optional_list(Some(String::new()));
        assert_eq!(tls.groups, None, "an empty group list must read as unset");

        let negotiated = handshake(&tls, SslVersion::TLS1_3)
            .expect("an empty group list must not break TLS 1.3");
        assert_eq!(negotiated, "TLSv1.3");
    }

    /// The same for a whitespace-only value, which is what a YAML
    /// `HTTP_SERVER_TLS_GROUPS: " "` produces.
    #[test]
    fn whitespace_only_groups_fall_back_to_the_default() {
        let mut tls = tls_config(TlsSecurityProfile::Modern);
        tls.groups = optional_list(Some("   ".to_string()));
        assert_eq!(tls.groups, None);

        let negotiated = handshake(&tls, SslVersion::TLS1_3)
            .expect("a whitespace-only group list must not break TLS 1.3");
        assert_eq!(negotiated, "TLSv1.3");
    }

    /// The other quiet one: an empty ciphersuite list is accepted by OpenSSL
    /// and disables every TLS 1.3 suite.
    #[test]
    fn empty_ciphersuites_fall_back_to_the_default() {
        let mut tls = tls_config(TlsSecurityProfile::Modern);
        tls.ciphersuites = optional_list(Some(String::new()));
        assert_eq!(tls.ciphersuites, None);

        let negotiated = handshake(&tls, SslVersion::TLS1_3)
            .expect("an empty ciphersuite list must not disable TLS 1.3");
        assert_eq!(negotiated, "TLSv1.3");
    }

    /// An empty cipher list is the one OpenSSL rejects outright, so before
    /// normalisation this took the server down at startup.
    #[test]
    fn empty_ciphers_fall_back_to_the_default() {
        let mut tls = tls_config(TlsSecurityProfile::Custom);
        tls.min_version = Some(TlsMinVersion::Tls1_2);
        tls.ciphers = optional_list(Some("  ".to_string()));
        assert_eq!(tls.ciphers, None);

        build_ssl_acceptor(&tls).expect("an empty cipher list must not fail the build");
    }

    /// End to end through the config conversion, which is where the
    /// normalisation actually happens for a deployed server.
    #[test]
    fn blank_tls_list_env_vars_are_ignored() {
        let config = HttpServerConfig::<MockEndpoint> {
            tls_enabled: true,
            tls_key_file: Some(PathBuf::from("/tmp/key.pem")),
            tls_certificate_file: Some(PathBuf::from("/tmp/cert.pem")),
            tls_security_profile: TlsSecurityProfile::Custom,
            tls_min_version: Some(TlsMinVersion::Tls1_2),
            tls_ciphers: Some(String::new()),
            tls_ciphersuites: Some("  ".to_string()),
            tls_groups: Some(String::new()),
            ..Default::default()
        };

        let builder = HttpServerBuilder::try_from(config).expect("blank values must not be fatal");
        let tls = builder.tls.expect("TLS should be configured");
        assert_eq!(tls.ciphers, None);
        assert_eq!(tls.ciphersuites, None);
        assert_eq!(tls.groups, None);
    }

    /// A PQC-only group list cannot serve a TLS 1.2 client that insists on
    /// ECDHE: the hybrid group is TLS 1.3 only, so the two have nothing in
    /// common. This is why the documentation tells operators to keep a
    /// classical group in the list unless the profile is TLS 1.3 only.
    #[test]
    fn pqc_only_groups_lock_out_tls12_ecdhe_clients() {
        const ECDHE_ONLY: &str = "ECDHE-RSA-AES128-GCM-SHA256";

        let mut tls = tls_config(TlsSecurityProfile::Intermediate);
        tls.groups = Some("X25519MLKEM768".to_string());
        let err = handshake_with(&tls, SslVersion::TLS1_2, ECDHE_ONLY)
            .expect_err("a PQC-only group list has nothing to offer TLS 1.2 ECDHE");
        assert!(
            err.contains("handshake failure"),
            "want a group negotiation failure, got: {err}"
        );

        // TLS 1.3 is unaffected, which is what makes this easy to miss.
        let mut tls13 = tls_config(TlsSecurityProfile::Intermediate);
        tls13.groups = Some("X25519MLKEM768".to_string());
        assert_eq!(
            handshake_with(&tls13, SslVersion::TLS1_3, ECDHE_ONLY).unwrap(),
            "TLSv1.3"
        );

        // Adding a classical group restores TLS 1.2 without losing PQC above.
        let mut both = tls_config(TlsSecurityProfile::Intermediate);
        both.groups = Some("X25519MLKEM768:X25519".to_string());
        assert_eq!(
            handshake_with(&both, SslVersion::TLS1_2, ECDHE_ONLY).unwrap(),
            "TLSv1.2"
        );
    }
}
