mod analyze;
mod auth;
mod cataloger;
mod client;
mod container;
mod error;
mod output;
mod target;

use crate::auth::OidcTokenProvider;
use crate::client::TrustifyClient;
use crate::output::OutputFormat;
use crate::target::Target;
use clap::Parser;
use std::process::ExitCode;
use url::Url;

/// Scan a target for known vulnerabilities using a trustify backend.
///
/// Supports directories, SBOM files (SPDX/CycloneDX), container images,
/// OCI archives, and bare PURLs. Discovered packages are submitted to
/// the trustify vulnerability analysis API for matching.
#[derive(Parser)]
#[command(name = "trustify-scanner", version)]
struct Cli {
    /// Scan target.
    ///
    /// Supported schemes: dir:PATH, sbom:PATH, pkg:PURL,
    /// registry:IMAGE:TAG, oci-archive:PATH.
    /// Plain paths are auto-detected; image-like references
    /// (containing `/`) are treated as registry targets.
    target: String,

    /// Trustify API base URL.
    #[arg(long, env = "TRUSTIFY_URL")]
    trustify_url: Url,

    /// Static bearer token for authentication.
    #[arg(long, env = "TRUSTIFY_TOKEN")]
    token: Option<String>,

    /// OIDC issuer URL (for client_credentials grant).
    #[arg(long, env = "ISSUER_URL")]
    issuer_url: Option<String>,

    /// OAuth2 client ID.
    #[arg(long, env = "CLIENT_ID")]
    client_id: Option<String>,

    /// OAuth2 client secret.
    #[arg(long, env = "CLIENT_SECRET")]
    client_secret: Option<String>,

    /// Output format.
    #[arg(short, long, default_value = "list")]
    output: OutputFormat,

    /// Exit with code 1 if vulnerabilities at or above this severity.
    #[arg(long)]
    fail_on: Option<Severity>,

    /// Upload the generated SBOM to trustify.
    #[arg(long)]
    upload: bool,

    /// Follow symbolic links when scanning directories.
    ///
    /// Disabled by default to prevent traversal outside the scan root.
    #[arg(long)]
    follow_links: bool,

    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// Severity threshold for `--fail-on`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn min_score(self) -> f64 {
        match self {
            Self::Low => 0.1,
            Self::Medium => 4.0,
            Self::High => 7.0,
            Self::Critical => 9.0,
        }
    }

    /// Check whether a vulnerability meets or exceeds this severity
    /// threshold by numeric score or severity string.
    fn matches(self, score: Option<f64>, severity: Option<&str>) -> bool {
        if let Some(s) = score
            && s >= self.min_score()
        {
            return true;
        }
        // Fall back to severity string when score is absent.
        if let Some(sev) = severity {
            let sev = sev.to_lowercase();
            match self {
                Self::Low => true,
                Self::Medium => sev != "low",
                Self::High => sev == "high" || sev == "critical",
                Self::Critical => sev == "critical",
            }
        } else {
            false
        }
    }
}

fn init_tracing(verbose: u8) {
    let filter = match verbose {
        0 => "warn,trustify_scanner=info",
        1 => "info,trustify_scanner=debug",
        _ => "debug,trustify_scanner=trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .with_target(false)
        .init();
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, error::Error> {
    // Parse target.
    let target: Target = cli.target.parse()?;

    tracing::info!(target = ?target, "scanning");

    // Build client.
    let client = build_client(
        cli.trustify_url,
        cli.token,
        cli.issuer_url,
        cli.client_id,
        cli.client_secret,
    )
    .await?;

    // Run scan.
    let result = analyze::scan(target, &client, cli.upload, cli.follow_links).await?;

    // Render output.
    output::render(&result, cli.output, cli.verbose)?;

    // Determine exit code based on --fail-on.
    if let Some(threshold) = cli.fail_on {
        let exceeds = result
            .vulnerabilities
            .iter()
            .any(|v| threshold.matches(v.score, v.severity.as_deref()));
        if exceeds {
            return Ok(ExitCode::from(1));
        }
    }

    Ok(ExitCode::SUCCESS)
}

async fn build_client(
    base_url: Url,
    token: Option<String>,
    issuer_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Result<TrustifyClient, error::Error> {
    if let Some(token) = token {
        return Ok(TrustifyClient::with_token(base_url, token));
    }

    if let (Some(issuer), Some(id), Some(secret)) = (issuer_url, client_id, client_secret) {
        let oidc = OidcTokenProvider::discover(&issuer, id, secret).await?;
        return Ok(TrustifyClient::with_oidc(base_url, oidc));
    }

    tracing::warn!("no authentication configured; requests will be unauthenticated");
    Ok(TrustifyClient::unauthenticated(base_url))
}
