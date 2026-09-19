/// Configuration for the notification service.
#[derive(clap::Args, Debug, Clone)]
pub struct NotificationConfig {
    /// Retention period for change_log entries (humantime, e.g. "1h", "30m", "1d")
    #[arg(long, env = "TRUSTD_CHANGE_LOG_RETENTION", default_value = "1d")]
    pub change_log_retention: humantime::Duration,

    /// Polling interval for the change_log fallback sweep
    #[arg(long, env = "TRUSTD_CHANGE_LOG_POLL_INTERVAL", default_value = "30s")]
    pub change_log_poll_interval: humantime::Duration,

    /// How often old change_log entries are cleaned up
    #[arg(long, env = "TRUSTD_CHANGE_LOG_CLEANUP_INTERVAL", default_value = "5m")]
    pub change_log_cleanup_interval: humantime::Duration,
}
