/// Configuration for the notification service.
#[derive(clap::Args, Debug, Clone)]
pub struct NotificationConfig {
    /// Retention period for change_log entries (humantime, e.g. "1h", "30m", "1d")
    #[arg(long, env = "TRUSTD_CHANGE_LOG_RETENTION", default_value = "1d")]
    pub change_log_retention: humantime::Duration,
}
