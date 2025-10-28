/// The default issuer when using `--devmode`.
pub const ISSUER_URL: &str = "http://localhost:8090/realms/trustify";

/// The default client id for the frontend
pub const FRONTEND_CLIENT_ID: &str = "frontend";

/// The default "service" client ID for devmode
pub const SERVICE_CLIENT_ID: &str = "testing-manager";

pub const PUBLIC_CLIENT_IDS: &[&str] = &[FRONTEND_CLIENT_ID];
pub const CONFIDENTIAL_CLIENT_IDS: &[&str] = &["walker", "testing-user", SERVICE_CLIENT_ID];

/// The clients which will be accepted by services when running with `--devmode`.
///
/// This also includes the "testing" clients, as this allows running the testsuite against an
/// already spun-up set of services.
pub const CLIENT_IDS: &[&str] = &[
    FRONTEND_CLIENT_ID,
    "walker",
    "testing-user",
    SERVICE_CLIENT_ID,
];

pub const SWAGGER_UI_CLIENT_ID: &str = FRONTEND_CLIENT_ID;

/// Static client secret for testing, configured in `deploy/compose/container_files/init-sso/data/client-*.json`.
///
/// This is not a secret. Don't use this in production.
pub const SSO_CLIENT_SECRET: &str = "R8A6KFeyxJsMDBhjfHbpZTIF0GWt43HP";

/// Get the issuer URL for `--devmode`.
///
/// This can be either the value of [`ISSUER_URL`], or it can be overridden using the environment
/// variable `ISSUER_URL`.
pub fn issuer_url() -> String {
    std::env::var("TRUSTD_ISSUER_URL").unwrap_or_else(|_| ISSUER_URL.to_string())
}

/// Get the client IDs for `--devmode`.
///
/// This combines the hardcoded [`CLIENT_IDS`] with any additional client IDs from the
/// `TRUSTD_ADDITIONAL_CLIENTS` environment variable (comma-separated).
pub fn client_ids() -> Vec<String> {
    let mut clients: Vec<String> = CLIENT_IDS.iter().map(|s| s.to_string()).collect();

    if let Ok(additional_clients) = std::env::var("TRUSTD_ADDITIONAL_CLIENTS") {
        for client in additional_clients.split(',') {
            let client = client.trim();
            if !client.is_empty() && !clients.contains(&client.to_string()) {
                clients.push(client.to_string());
            }
        }
    }

    clients
}

#[cfg(test)]
mod test {
    use super::*;

    /// Ensure that `CLIENT_IDS` is a union of public and configuration client IDs.
    ///
    /// As we can't have a const way of creating a union of slices (without any additional
    /// dependency), we simply use a test to ensure this.
    #[test]
    fn test_client_id_union() {
        assert_eq!(
            CLIENT_IDS,
            PUBLIC_CLIENT_IDS
                .iter()
                .chain(CONFIDENTIAL_CLIENT_IDS.iter())
                .copied()
                .collect::<Vec<&str>>()
        )
    }
}
