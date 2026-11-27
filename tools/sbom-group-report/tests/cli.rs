mod common;

use std::process::{Command, Output};

use common::Server;
use serde_json::{Value, json};

const ROOT: &str = "00000000-0000-0000-0000-000000000001";
const CHILD: &str = "00000000-0000-0000-0000-000000000002";

/// Run the binary against `server`, with the real environment cleared so a
/// developer's own `TRUSTIFY_*` settings cannot change the result.
#[allow(
    clippy::unwrap_used,
    reason = "failing to spawn the binary is a broken test"
)]
fn run(server: &Server, args: &[&str]) -> Output {
    run_with(&server.url, args, &[])
}

/// As `run`, but against an explicit URL and with credential variables set.
#[allow(
    clippy::unwrap_used,
    reason = "failing to spawn the binary is a broken test"
)]
fn run_with(url: &str, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sbom-group-report"));
    for name in [
        "TRUSTIFY_URL",
        "TRUSTIFY_TOKEN",
        "ISSUER_URL",
        "CLIENT_ID",
        "CLIENT_SECRET",
    ] {
        command.env_remove(name);
    }
    command
        .envs(envs.iter().copied())
        .args(["root", "--url", url])
        .args(args)
        .output()
        .unwrap()
}

fn sbom(id: usize) -> Value {
    json!({
        "id": format!("urn:uuid:10000000-0000-0000-0000-{id:012}"),
        "name": format!("service-{id}"), "number_of_packages": 2,
        "authors": [], "suppliers": [], "data_licenses": [], "described_by": [], "labels": {},
        "published": null, "ingested": "2026-11-04T00:00:00Z", "size": 1,
        "sha256": "0".repeat(64), "sha384": "0".repeat(96), "sha512": "0".repeat(128)
    })
}

#[test]
fn nested_cycle_deduplicates_sboms_and_links_to_the_instance() {
    let server = Server::new(|_, request| {
        if request.path.starts_with("/api/v3/group/sbom?") {
            json!({"items": [
                {"id": ROOT, "name": "root", "parent": CHILD},
                {"id": CHILD, "name": "child", "parent": ROOT}
            ], "total": 2})
        } else if request.path.starts_with("/api/v3/sbom?") {
            let items = if request.path.contains(CHILD) {
                vec![sbom(1), sbom(2)]
            } else {
                vec![sbom(1)]
            };
            json!({"total": items.len(), "items": items})
        } else {
            assert!(request.path.ends_with("/advisory"));
            json!([])
        }
    });
    let output = run(
        &server,
        &["--format", "csv", "--max-sboms", "2", "--max-depth", "1"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let csv = String::from_utf8(output.stdout).unwrap();
    assert_eq!(csv.lines().count(), 3);
    assert!(csv.contains(&format!(
        "{}/sboms/urn:uuid:10000000-0000-0000-0000-000000000001?sd%3AactiveTab=vulnerabilities",
        server.url
    )));
    let output = run(&server, &["--max-depth", "1"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let html = String::from_utf8(output.stdout).unwrap();
    assert!(html.contains(&format!(
        "href=\"{}/sboms/urn:uuid:10000000-0000-0000-0000-000000000001?sd%3AactiveTab=vulnerabilities\" target=\"_blank\" rel=\"noopener noreferrer\"",
        server.url
    )));
}

#[test]
fn depth_limit_fails_before_fetching_sboms_or_writing_a_report() {
    let server = Server::new(|_, _| {
        json!({"items": [
        {"id": ROOT, "name": "root"}, {"id": CHILD, "name": "child", "parent": ROOT}
    ], "total": 2})
    });
    let output = run(&server, &["--max-depth", "0"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--max-depth 0"));
    assert!(output.stdout.is_empty());
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn sbom_limit_stops_pagination_with_or_without_a_total() {
    for total in [json!(501), Value::Null] {
        let server = Server::new(move |_, request| {
            if request.path.starts_with("/api/v3/group/sbom?") {
                json!({"items": [{"id": ROOT, "name": "root"}], "total": 1})
            } else {
                assert!(request.path.starts_with("/api/v3/sbom?"));
                json!({"items": [sbom(1), sbom(2)], "total": total})
            }
        });
        let output = run(&server, &["--max-sboms", "1"]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--max-sboms 1"));
        assert!(output.stdout.is_empty());
        assert_eq!(
            server.requests().len(),
            2,
            "only the first inventory page is fetched"
        );
    }
}

#[test]
fn sbom_limit_applies_across_child_groups() {
    let server = Server::new(|_, request| {
        if request.path.starts_with("/api/v3/group/sbom?") {
            json!({"items": [
                {"id": ROOT, "name": "root"}, {"id": CHILD, "name": "child", "parent": ROOT}
            ], "total": 2})
        } else {
            assert!(request.path.starts_with("/api/v3/sbom?"));
            let items = if request.path.contains(CHILD) {
                vec![sbom(3)]
            } else {
                vec![sbom(1), sbom(2)]
            };
            json!({"total": items.len(), "items": items})
        }
    });
    let output = run(&server, &["--max-sboms", "2"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--max-sboms 2"));
    assert!(output.stdout.is_empty());
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn group_inventory_is_bounded() {
    let server = Server::new(|_, _| json!({"items": [], "total": 10_001}));
    let output = run(&server, &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("group safety limit"));
    assert_eq!(server.requests().len(), 1);
}

fn oidc_server(mode: &'static str) -> Server {
    Server::new(move |url, request| match request.path.as_str() {
        "/.well-known/openid-configuration" => {
            let mut metadata = json!({"issuer": url, "token_endpoint": format!("{url}/token")});
            match mode {
                "bad-issuer" => metadata["issuer"] = json!("https://other.example"),
                "insecure-endpoint" => {
                    metadata["token_endpoint"] = json!("http://identity.example/token")
                }
                "post" => {
                    metadata["token_endpoint_auth_methods_supported"] =
                        json!(["client_secret_post"])
                }
                "basic" => {
                    metadata["token_endpoint_auth_methods_supported"] =
                        json!(["client_secret_basic"])
                }
                "unsupported" => {
                    metadata["token_endpoint_auth_methods_supported"] = json!(["private_key_jwt"])
                }
                _ => {}
            }
            metadata
        }
        "/token" => {
            assert_eq!(request.method, "POST");
            assert!(request.body.contains("grant_type=client_credentials"));
            if mode == "post" {
                assert!(request.body.contains("client_secret=test-secret"));
                assert!(request.body.contains("client_id=test-client"));
                assert!(!request.headers.contains_key("authorization"));
            } else {
                assert!(request.headers["authorization"].starts_with("Basic "));
                assert!(!request.body.contains("client_secret"));
                if mode == "escaped" {
                    assert_eq!(
                        request.headers["authorization"],
                        "Basic dGVzdCUzQStjbGllbnQ6dGVzdCUyQnNlY3JldCUyNiUzRA=="
                    );
                }
            }
            json!({"access_token": "test-token", "token_type": "Bearer", "expires_in": match mode {
                "overflow" => u64::MAX, "expired" => 0, _ => 300
            }})
        }
        path if path.starts_with("/api/v3/group/sbom?") => {
            assert_eq!(request.headers["authorization"], "Bearer test-token");
            json!({"items": [{"id": ROOT, "name": "root"}], "total": 1})
        }
        path => {
            assert!(path.starts_with("/api/v3/sbom?"));
            assert_eq!(request.headers["authorization"], "Bearer test-token");
            json!({"items": [], "total": 0})
        }
    })
}

fn run_oidc(server: &Server) -> Output {
    run_with(
        &server.url,
        &["--issuer-url", &server.url, "--client-id", "test-client"],
        &[("CLIENT_SECRET", "test-secret")],
    )
}

#[test]
fn oidc_supports_basic_and_post_and_caches_tokens() {
    for mode in ["basic", "post", "default"] {
        let server = oidc_server(mode);
        let output = run_oidc(&server);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            server
                .requests()
                .iter()
                .filter(|request| request.path == "/token")
                .count(),
            1
        );
    }
}

#[test]
fn oidc_rejects_unsafe_discovery_before_sending_credentials() {
    for (mode, expected) in [
        ("bad-issuer", "issuer does not match"),
        ("insecure-endpoint", "must use HTTPS"),
        ("unsupported", "must support client_secret"),
    ] {
        let server = oidc_server(mode);
        let output = run_oidc(&server);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
        assert_eq!(server.requests().len(), 1, "no credentials are posted");
    }
}

#[test]
fn oidc_basic_encodes_special_characters_in_credentials() {
    let server = oidc_server("escaped");
    let output = run_with(
        &server.url,
        &["--issuer-url", &server.url, "--client-id", "test: client"],
        &[("CLIENT_SECRET", "test+secret&=")],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn credentials_are_not_sent_over_plain_http_without_opting_in() {
    let token = [("TRUSTIFY_TOKEN", "test-token")];
    let output = run_with("http://trustify.example:8080", &[], &token);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing to send credentials"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    // Opting in gets past the check and fails later, on the unreachable host.
    let output = run_with("http://trustify.example:8080", &["--insecure"], &token);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("refusing to send credentials"));
}

#[test]
fn oidc_rejects_overflowing_expiry_without_panicking() {
    let server = oidc_server("overflow");
    let output = run_oidc(&server);
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("expires_in is too large"));
    assert!(!error.contains("test-secret") && !error.contains("test-token"));
}

#[test]
fn oidc_refreshes_expired_tokens() {
    let server = oidc_server("expired");
    let output = run_oidc(&server);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|request| request.path == "/token")
            .count(),
        2
    );
}
