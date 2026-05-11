use serde_json::{self, Value, from_slice, from_str, json, to_string_pretty};
use tokio::process::Command;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_sbom_response() -> Value {
    json!({
        "items": [
            {
                "id": "019c99b2-32cb-7ce0-a1f4-353e398627e4",
                "name": "my-app",
                "document_id": "doc-001",
                "ingested": "2024-01-15T10:30:45Z",
                "published": "2024-01-10T08:00:00Z",
                "size": 1024
            },
            {
                "id": "019c99b2-32cb-7ce0-a1f4-353e398627e5",
                "name": "other-app",
                "document_id": "doc-002",
                "ingested": "2024-02-20T14:20:30Z",
                "published": "2024-02-18T09:15:00Z",
                "size": 2048
            }
        ],
        "total": 2
    })
}

fn sample_advisory_response() -> Value {
    json!({
        "items": [
            {
                "uuid": "019c99b2-32cb-7ce0-a1f4-353e398627e4",
                "identifier": "CVE-2024-1234",
                "published": "2024-01-15T10:30:45Z",
                "ingested": "2024-01-16T08:00:00Z"
            },
            {
                "uuid": "019c99b2-32cb-7ce0-a1f4-353e398627e5",
                "identifier": "CVE-2024-5678",
                "published": "2024-02-20T14:20:30Z",
                "ingested": "2024-02-21T09:15:00Z"
            }
        ],
        "total": 2
    })
}

#[tokio::test]
async fn cli_sbom_list_full_format() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_sbom_response()))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args(["--url", &server.uri(), "sbom", "list"])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let json: Value = from_slice(&output.stdout).unwrap();
    assert_eq!(
        json["items"][0]["id"],
        "019c99b2-32cb-7ce0-a1f4-353e398627e4"
    );
    assert_eq!(json["total"], 2);
}

#[tokio::test]
async fn cli_sbom_list_id_format() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_sbom_response()))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args(["--url", &server.uri(), "sbom", "list", "--format", "id"])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("019c99b2-32cb-7ce0-a1f4-353e398627e4"));
    assert!(out.contains("019c99b2-32cb-7ce0-a1f4-353e398627e5"));
}

#[tokio::test]
async fn cli_sbom_list_name_format() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_sbom_response()))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args(["--url", &server.uri(), "sbom", "list", "--format", "name"])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    let json: Value = from_str(&out).unwrap();
    assert_eq!(json[0]["id"], "019c99b2-32cb-7ce0-a1f4-353e398627e4");
    assert_eq!(json[0]["name"], "my-app");
}

#[tokio::test]
async fn cli_sbom_list_short_format() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_sbom_response()))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args(["--url", &server.uri(), "sbom", "list", "--format", "short"])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    let json: Value = from_str(&out).unwrap();
    assert_eq!(json[0]["id"], "019c99b2-32cb-7ce0-a1f4-353e398627e4");
    assert_eq!(json[0]["ingested"], "2024-01-15T10:30:45Z");
    assert_eq!(json[0]["published"], "2024-01-10T08:00:00Z");
    assert_eq!(json[0]["size"], 1024);
}

#[tokio::test]
async fn cli_sbom_list_with_query() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .and(query_param("q", "name=my-app"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [sample_sbom_response()["items"][0]],
            "total": 1
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "list",
            "--query",
            "name=my-app",
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    let json: Value = from_str(&out).unwrap();
    assert_eq!(json["total"], 1);
    assert_eq!(json["items"][0]["name"], "my-app");
}

#[tokio::test]
async fn cli_sbom_list_with_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .and(query_param("limit", "10"))
        .and(query_param("offset", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "list",
            "--limit",
            "10",
            "--offset",
            "20",
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    assert_eq!(out.trim(), "{\"items\":[],\"total\":0}");
}

#[tokio::test]
async fn cli_sbom_list_with_sort() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .and(query_param("sort", "published:desc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_sbom_response()))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "list",
            "--sort",
            "published:desc",
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    let json: Value = from_str(&out).unwrap();
    assert_eq!(json["total"], 2);
}

#[tokio::test]
async fn cli_sbom_get_by_id() {
    let server = MockServer::start().await;
    let sbom_id = "019c99b2-32cb-7ce0-a1f4-353e398627e4";

    Mock::given(method("GET"))
        .and(path(format!("/api/v3/sbom/{}", sbom_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": sbom_id,
            "name": "my-app",
            "document_id": "doc-001",
            "ingested": "2024-01-15T10:30:45Z",
            "published": "2024-01-10T08:00:00Z"
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args(["--url", &server.uri(), "sbom", "get", sbom_id])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    let json: Value = from_str(&out).unwrap();
    assert_eq!(json["id"], sbom_id);
    assert_eq!(json["name"], "my-app");
}

#[tokio::test]
async fn cli_sbom_delete_by_id() {
    let server = MockServer::start().await;
    let sbom_id = "019c99b2-32cb-7ce0-a1f4-353e398627e4";

    Mock::given(method("DELETE"))
        .and(path(format!("/api/v3/sbom/{}", sbom_id)))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args(["--url", &server.uri(), "sbom", "delete", "--id", sbom_id])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("Deleted SBOM ID"));
}

#[tokio::test]
async fn cli_sbom_delete_by_id_dry_run() {
    let server = MockServer::start().await;
    let sbom_id = "019c99b2-32cb-7ce0-a1f4-353e398627e4";

    Mock::given(method("DELETE"))
        .and(path(format!("/api/v3/sbom/{}", sbom_id)))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "delete",
            "--id",
            sbom_id,
            "--dry-run",
        ])
        .output()
        .await
        .unwrap();

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    println!(
        "status: {}, stdout: {}, stderr: {}",
        output.status, stdout, stderr
    );
    assert!(output.status.success());
    assert!(stdout.contains("Deleted SBOM ID") || stdout.contains(sbom_id));
}

#[tokio::test]
async fn cli_sbom_delete_by_query_dry_run() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": "019c99b2-32cb-7ce0-a1f4-353e398627e4",
                "document_id": "doc-001"
            }],
            "total": 1
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "delete",
            "--query",
            "name=my-app",
            "--dry-run",
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(err.contains("DRY-RUN") || err.contains("Would delete"));
}

#[tokio::test]
async fn cli_sbom_duplicates_find_default() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args(["--url", &server.uri(), "sbom", "duplicates", "find"])
        .output()
        .await
        .unwrap();

    let err = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success());
    assert!(err.contains("No SBOMs found"));
}

#[tokio::test]
async fn cli_sbom_duplicates_find_custom_params() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "duplicates",
            "find",
            "-j",
            "8",
            "-b",
            "500",
        ])
        .output()
        .await
        .unwrap();

    let err = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success());
    assert!(err.contains("No SBOMs found"));
}

fn create_test_duplicates_file(path: &str) {
    let content = json!([
        {
            "document_id": "doc-001",
            "published": "2024-01-10T08:00:00Z",
            "id": "019c99b2-32cb-7ce0-a1f4-353e398627e4",
            "duplicates": ["019c99b2-32cb-7ce0-a1f4-353e398627e5", "019c99b2-32cb-7ce0-a1f4-353e398627e6"]
        }
    ]);

    #[allow(clippy::unwrap_used)]
    std::fs::write(path, to_string_pretty(&content).unwrap()).unwrap();
}

#[tokio::test]
async fn cli_sbom_duplicates_delete_dry_run() {
    let server = MockServer::start().await;
    let duplicates_file = std::env::temp_dir()
        .join("test_duplicates.json")
        .to_string_lossy()
        .to_string();

    create_test_duplicates_file(&duplicates_file);

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "duplicates",
            "delete",
            "--dry-run",
            "--input",
            &duplicates_file,
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(err.contains("DRY-RUN") || err.contains("Would delete"));
}

#[tokio::test]
async fn cli_sbom_prune_dry_run() {
    let server = MockServer::start().await;
    let output_file = std::env::temp_dir()
        .join("test_sboms_prune.json")
        .to_string_lossy()
        .to_string();

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "prune",
            "--dry-run",
            "--output",
            &output_file,
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("DRY-RUN") || out.contains("Would prune"));
}

#[tokio::test]
async fn cli_sbom_prune_published_before() {
    let server = MockServer::start().await;
    let output_file = std::env::temp_dir()
        .join("test_sboms_prune_pub.json")
        .to_string_lossy()
        .to_string();

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "prune",
            "--published-before",
            "2026-01-15T10:30:45Z",
            "--output",
            &output_file,
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
}

#[tokio::test]
async fn cli_sbom_prune_by_label() {
    let server = MockServer::start().await;
    let output_file = std::env::temp_dir()
        .join("test_sboms_prune_label.json")
        .to_string_lossy()
        .to_string();

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "prune",
            "--label",
            "type=spdx",
            "--output",
            &output_file,
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
}

#[tokio::test]
async fn cli_sbom_prune_keep_latest() {
    let server = MockServer::start().await;
    let output_file = std::env::temp_dir()
        .join("test_sboms_prune_keep.json")
        .to_string_lossy()
        .to_string();

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "sbom",
            "prune",
            "--keep-latest",
            "5",
            "--output",
            &output_file,
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
}

#[tokio::test]
async fn cli_advisory_list() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_advisory_response()))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args(["--url", &server.uri(), "advisory", "list"])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    let json: Value = from_str(&out).unwrap();
    assert_eq!(
        json["items"][0]["uuid"],
        "019c99b2-32cb-7ce0-a1f4-353e398627e4"
    );
    assert_eq!(json["total"], 2);
}

#[tokio::test]
async fn cli_advisory_list_with_query() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .and(query_param("q", "identifier=CVE-2024-1234"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [sample_advisory_response()["items"][0]],
            "total": 1
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "advisory",
            "list",
            "--query",
            "identifier=CVE-2024-1234",
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    let json: Value = from_str(&out).unwrap();
    assert_eq!(json["total"], 1);
    assert_eq!(json["items"][0]["identifier"], "CVE-2024-1234");
}

#[tokio::test]
async fn cli_advisory_list_with_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .and(query_param("limit", "10"))
        .and(query_param("offset", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "advisory",
            "list",
            "--limit",
            "10",
            "--offset",
            "20",
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    assert_eq!(out.trim(), "{\n  \"items\": [],\n  \"total\": 0\n}");
}

#[tokio::test]
async fn cli_advisory_prune_dry_run() {
    let server = MockServer::start().await;
    let output_file = std::env::temp_dir()
        .join("test_advisories_prune.json")
        .to_string_lossy()
        .to_string();

    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "advisory",
            "prune",
            "--dry-run",
            "--output",
            &output_file,
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("DRY-RUN") || out.contains("Would delete"));
}

#[tokio::test]
async fn cli_advisory_prune_older_than() {
    let server = MockServer::start().await;
    let output_file = std::env::temp_dir()
        .join("test_advisories_prune_older.json")
        .to_string_lossy()
        .to_string();

    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "advisory",
            "prune",
            "--older-than",
            "90",
            "--output",
            &output_file,
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
}

#[tokio::test]
async fn cli_advisory_prune_keep_latest() {
    let server = MockServer::start().await;
    let output_file = std::env::temp_dir()
        .join("test_advisories_prune_keep.json")
        .to_string_lossy()
        .to_string();

    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total": 0
        })))
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trustify"))
        .args([
            "--url",
            &server.uri(),
            "advisory",
            "prune",
            "--keep-latest",
            "5",
            "--output",
            &output_file,
        ])
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
}
