/// Configuration for the correlation service.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct CorrelationConfig {
    /// Polling interval in seconds for the change_log fallback sweep.
    #[arg(long, env = "TRUSTD_CORRELATION_POLL_INTERVAL", default_value = "30")]
    pub correlation_poll_interval_secs: u64,

    /// Debounce window in seconds before reloading after a change event.
    #[arg(long, env = "TRUSTD_CORRELATION_DEBOUNCE_SECS", default_value = "2")]
    pub correlation_debounce_secs: u64,
}
