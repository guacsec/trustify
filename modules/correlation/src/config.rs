/// Configuration for the correlation service.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct CorrelationConfig {
    #[arg(
        long,
        env = "TRUSTD_CORRELATION_ENABLED",
        default_value = "false",
        help = "Enable the in-memory correlation service (v4 API)."
    )]
    pub correlation_enabled: bool,
}
