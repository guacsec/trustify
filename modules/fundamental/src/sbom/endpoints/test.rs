use crate::{
    sbom::model::{SbomPackage, SbomSummary},
    test::{caller, label::Api},
};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use flate2::bufread::GzDecoder;
use serde_json::{Value, json};
use std::{io::Read, str::FromStr};
use test_context::test_context;
use test_log::test;
use trustify_common::{id::Id, model::PaginatedResults};
use trustify_module_ingestor::{model::IngestResult, service::Format};
use trustify_module_storage::service::{StorageBackend, StorageKey};
use trustify_test_context::{
    TrustifyContext, call::CallService, document_bytes, subset::ContainsSubset,
};
use urlencoding::encode;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn fetch_unique_licenses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?
        .id
        .to_string();

    let uri = format!("/api/v2/sbom/{id}/all-license-ids");
    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    let expected_result = json!([
      {
        "license_name": "(FTL or GPLv2+) and BSD and MIT and Public Domain and zlib with acknowledgement",
        "license_id": "(FTL or GPLv2+) and BSD and MIT and Public Domain and zlib with acknowledgement"
      },
      {
        "license_name": "(GPL+ OR Artistic) AND Artistic 2.0 AND UCD",
        "license_id": "(GPL+ OR Artistic) AND Artistic 2.0 AND UCD"
      },
      {
        "license_name": "(GPL+ OR Artistic) AND BSD",
        "license_id": "(GPL+ OR Artistic) AND BSD"
      },
      {
        "license_name": "(GPL+ OR Artistic) AND HSRL AND MIT AND UCD",
        "license_id": "(GPL+ OR Artistic) AND HSRL AND MIT AND UCD"
      },
      {
        "license_name": "(GPLv2+ OR AFL) AND GPLv2+",
        "license_id": "(GPLv2+ OR AFL) AND GPLv2+"
      },
      {
        "license_name": "(LGPLv2+ OR GPLv2+ OR MPL) AND (Netscape OR GPLv2+ OR LGPLv2+)",
        "license_id": "(LGPLv2+ OR GPLv2+ OR MPL) AND (Netscape OR GPLv2+ OR LGPLv2+)"
      },
      {
        "license_name": "(LGPLv3+ OR GPLv2+) AND GPLv3+",
        "license_id": "(LGPLv3+ OR GPLv2+) AND GPLv3+"
      },
      {
        "license_name": "[{'license': {'id': 'Apache-2.0'}}]",
        "license_id": "[{'license': {'id': 'Apache-2.0'}}]"
      },
      {
        "license_name": "[{'license': {'id': None}}]",
        "license_id": "[{'license': {'id': None}}]"
      },
      {
        "license_name": "AFL AND GPLv2+",
        "license_id": "AFL AND GPLv2+"
      },
      {
        "license_name": "Apache-2.0",
        "license_id": "Apache-2.0"
      },
      {
        "license_name": "Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause",
        "license_id": "Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause"
      },
      {
        "license_name": "Apache-2.0 AND BSD-3-Clause",
        "license_id": "Apache-2.0 AND BSD-3-Clause"
      },
      {
        "license_name": "Apache-2.0 AND JSON AND MIT",
        "license_id": "Apache-2.0 AND JSON AND MIT"
      },
      {
        "license_name": "Apache-2.0 AND MIT",
        "license_id": "Apache-2.0 AND MIT"
      },
      {
        "license_name": "Apache-2.0 AND Unlicense",
        "license_id": "Apache-2.0 AND Unlicense"
      },
      {
        "license_name": "ASL 2.0",
        "license_id": "ASL 2.0"
      },
      {
        "license_name": "ASL 2.0 AND BSD",
        "license_id": "ASL 2.0 AND BSD"
      },
      {
        "license_name": "BSD",
        "license_id": "BSD"
      },
      {
        "license_name": "BSD AND GPLv2",
        "license_id": "BSD AND GPLv2"
      },
      {
        "license_name": "BSD AND LGPLv2+",
        "license_id": "BSD AND LGPLv2+"
      },
      {
        "license_name": "BSD OR GPL+",
        "license_id": "BSD OR GPL+"
      },
      {
        "license_name": "BSD-2-Clause",
        "license_id": "BSD-2-Clause"
      },
      {
        "license_name": "BSD-2-Clause AND BSD-2-Clause-Views",
        "license_id": "BSD-2-Clause AND BSD-2-Clause-Views"
      },
      {
        "license_name": "BSD-2-Clause AND BSD-3-Clause",
        "license_id": "BSD-2-Clause AND BSD-3-Clause"
      },
      {
        "license_name": "BSD-2-Clause AND BSD-3-Clause AND ISC",
        "license_id": "BSD-2-Clause AND BSD-3-Clause AND ISC"
      },
      {
        "license_name": "BSD-2-Clause AND MIT",
        "license_id": "BSD-2-Clause AND MIT"
      },
      {
        "license_name": "BSD-2-Clause-Views AND MIT",
        "license_id": "BSD-2-Clause-Views AND MIT"
      },
      {
        "license_name": "BSD-3-Clause",
        "license_id": "BSD-3-Clause"
      },
      {
        "license_name": "BSD-3-Clause AND BSD-3-Clause-Clear",
        "license_id": "BSD-3-Clause AND BSD-3-Clause-Clear"
      },
      {
        "license_name": "BSD-3-Clause AND MIT",
        "license_id": "BSD-3-Clause AND MIT"
      },
      {
        "license_name": "BSD-3-Clause OR BSD-3-Clause OR ISC",
        "license_id": "BSD-3-Clause OR BSD-3-Clause OR ISC"
      },
      {
        "license_name": "CC-BY-SA-4.0 AND ISC",
        "license_id": "CC-BY-SA-4.0 AND ISC"
      },
      {
        "license_name": "CC0-1.0",
        "license_id": "CC0-1.0"
      },
      {
        "license_name": "CC0-1.0 AND MIT",
        "license_id": "CC0-1.0 AND MIT"
      },
      {
        "license_name": "CDDL-1.0 OR GPL-2.0-with-classpath-exception",
        "license_id": "CDDL-1.0 OR GPL-2.0-with-classpath-exception"
      },
      {
        "license_name": "CDDL-1.1 OR GPL-2.0-with-classpath-exception",
        "license_id": "CDDL-1.1 OR GPL-2.0-with-classpath-exception"
      },
      {
        "license_name": "Copyright only AND (Artistic OR GPL+)",
        "license_id": "Copyright only AND (Artistic OR GPL+)"
      },
      {
        "license_name": "EPL-1.0",
        "license_id": "EPL-1.0"
      },
      {
        "license_name": "EPL-2.0 OR GNU General Public License, version 2 with the GNU Classpath Exception",
        "license_id": "EPL-2.0 OR GNU General Public License, version 2 with the GNU Classpath Exception"
      },
      {
        "license_name": "GPL+ OR Artistic",
        "license_id": "GPL+ OR Artistic"
      },
      {
        "license_name": "GPL-2.0-only AND MIT",
        "license_id": "GPL-2.0-only AND MIT"
      },
      {
        "license_name": "GPLv2",
        "license_id": "GPLv2"
      },
      {
        "license_name": "GPLv2 AND GPLv2+ AND LGPLv2 AND MIT",
        "license_id": "GPLv2 AND GPLv2+ AND LGPLv2 AND MIT"
      },
      {
        "license_name": "GPLv2+",
        "license_id": "GPLv2+"
      },
      {
        "license_name": "GPLv2+ AND BSD",
        "license_id": "GPLv2+ AND BSD"
      },
      {
        "license_name": "GPLv2+ AND GPL+",
        "license_id": "GPLv2+ AND GPL+"
      },
      {
        "license_name": "GPLv2+ AND LGPLv2+",
        "license_id": "GPLv2+ AND LGPLv2+"
      },
      {
        "license_name": "GPLv2+ OR LGPLv3+",
        "license_id": "GPLv2+ OR LGPLv3+"
      },
      {
        "license_name": "GPLv3",
        "license_id": "GPLv3"
      },
      {
        "license_name": "GPLv3+",
        "license_id": "GPLv3+"
      },
      {
        "license_name": "GPLv3+ AND (GPLv2+ OR LGPLv3+)",
        "license_id": "GPLv3+ AND (GPLv2+ OR LGPLv3+)"
      },
      {
        "license_name": "GPLv3+ AND GFDL AND BSD AND MIT",
        "license_id": "GPLv3+ AND GFDL AND BSD AND MIT"
      },
      {
        "license_name": "GPLv3+ and GPLv3+ with exceptions and GPLv2+ and GPLv2+ with exceptions and GPL+ and LGPLv2+ and LGPLv3+ and BSD and Public Domain and GFDL",
        "license_id": "GPLv3+ and GPLv3+ with exceptions and GPLv2+ and GPLv2+ with exceptions and GPL+ and LGPLv2+ and LGPLv3+ and BSD and Public Domain and GFDL"
      },
      {
        "license_name": "GPLv3+ OR BSD",
        "license_id": "GPLv3+ OR BSD"
      },
      {
        "license_name": "ISC",
        "license_id": "ISC"
      },
      {
        "license_name": "ISC AND JSON",
        "license_id": "ISC AND JSON"
      },
      {
        "license_name": "ISC AND MIT",
        "license_id": "ISC AND MIT"
      },
      {
        "license_name": "JasPer",
        "license_id": "JasPer"
      },
      {
        "license_name": "JSON AND MIT",
        "license_id": "JSON AND MIT"
      },
      {
        "license_name": "LGPL-3.0-or-later OR Apache-2.0",
        "license_id": "LGPL-3.0-or-later OR Apache-2.0"
      },
      {
        "license_name": "LGPLv2",
        "license_id": "LGPLv2"
      },
      {
        "license_name": "LGPLv2 OR MPLv1.1",
        "license_id": "LGPLv2 OR MPLv1.1"
      },
      {
        "license_name": "LGPLv2+",
        "license_id": "LGPLv2+"
      },
      {
        "license_name": "LGPLv2+ AND GPLv2+ AND GPLv3+",
        "license_id": "LGPLv2+ AND GPLv2+ AND GPLv3+"
      },
      {
        "license_name": "LGPLv2+ AND GPLv3+",
        "license_id": "LGPLv2+ AND GPLv3+"
      },
      {
        "license_name": "LGPLv2+ AND MIT AND GPLv2+",
        "license_id": "LGPLv2+ AND MIT AND GPLv2+"
      },
      {
        "license_name": "LGPLv3+ AND GPLv3+ AND GFDL",
        "license_id": "LGPLv3+ AND GPLv3+ AND GFDL"
      },
      {
        "license_name": "MIT",
        "license_id": "MIT"
      },
      {
        "license_name": "MIT AND ASL 2.0 AND CC-BY AND GPLv3",
        "license_id": "MIT AND ASL 2.0 AND CC-BY AND GPLv3"
      },
      {
        "license_name": "MIT AND MPL-1.0",
        "license_id": "MIT AND MPL-1.0"
      },
      {
        "license_name": "MIT AND WTFPL",
        "license_id": "MIT AND WTFPL"
      },
      {
        "license_name": "MIT/X License, GPL/CDDL, ASL2",
        "license_id": "MIT/X License, GPL/CDDL, ASL2"
      },
      {
        "license_name": "MPL-2.0",
        "license_id": "MPL-2.0"
      },
      {
        "license_name": "NOASSERTION",
        "license_id": "NOASSERTION"
      },
      {
        "license_name": "Public Domain",
        "license_id": "Public Domain"
      },
      {
        "license_name": "Python-2.0",
        "license_id": "Python-2.0"
      },
      {
        "license_name": "Zlib",
        "license_id": "Zlib"
      },
      {
        "license_name": "Zlib AND Boost",
        "license_id": "Zlib AND Boost"
      },
      {
        "license_name": "Zlib AND Sendmail AND LGPLv2+",
        "license_id": "Zlib AND Sendmail AND LGPLv2+"
      }
    ]);
    log::debug!("{:#}", json!(response));
    assert!(expected_result.contains_subset(response.clone()));

    let id = ctx
        .ingest_document("cyclonedx/application.cdx.json")
        .await?
        .id
        .to_string();

    let uri = format!("/api/v2/sbom/{id}/all-license-ids");
    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    let expected_result = json!([
      {
        "license_name": "Apache-2.0",
        "license_id": "Apache-2.0"
      },
      {
        "license_name": "BSD-2-Clause",
        "license_id": "BSD-2-Clause"
      },
      {
        "license_name": "BSD-3-Clause",
        "license_id": "BSD-3-Clause"
      },
      {
        "license_name": "CC0-1.0",
        "license_id": "CC0-1.0"
      },
      {
        "license_name": "EPL 1.0",
        "license_id": "EPL 1.0"
      },
      {
        "license_name": "EPL-1.0",
        "license_id": "EPL-1.0"
      },
      {
        "license_name": "EPL-2.0",
        "license_id": "EPL-2.0"
      },
      {
        "license_name": "GNU Lesser General Public License",
        "license_id": "GNU Lesser General Public License"
      },
      {
        "license_name": "GPL-2.0-with-classpath-exception",
        "license_id": "GPL-2.0-with-classpath-exception"
      },
      {
        "license_name": "LGPL-2.1-only",
        "license_id": "LGPL-2.1-only"
      },
      {
        "license_name": "MIT",
        "license_id": "MIT"
      },
      {
        "license_name": "MPL-2.0",
        "license_id": "MPL-2.0"
      },
      {
        "license_name": "Openfont-1.1",
        "license_id": "Openfont-1.1"
      },
      {
        "license_name": "The GNU General Public License, v2 with Universal FOSS Exception, v1.0",
        "license_id": "The GNU General Public License, v2 with Universal FOSS Exception, v1.0"
      }
    ]);
    log::debug!("{:#}", json!(response));
    assert!(expected_result.contains_subset(response.clone()));

    // properly formatted but not existent Id
    let req = TestRequest::get().uri("/api/v2/sbom/sha256:e5c850b67868563002801668950832278f8093308b3a3c57931f591442ed3160/all-license-ids").to_request();
    let response = app.call_service(req).await;
    assert_eq!(StatusCode::NOT_FOUND, response.status());

    // badly formatted Id
    let req = TestRequest::get()
        .uri("/api/v2/sbom/sha123:1234/all-license-ids")
        .to_request();
    let response = app.call_service(req).await;
    assert_eq!(StatusCode::BAD_REQUEST, response.status());

    // Test license IDs are case-insensitive https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/#case-sensitivity
    // because, so far, the test ingested `Apache-2.0` licenses but the next SBOM contains
    // the license ID `APACHE-2.0` (the same for `BSD-2-Clause`)
    let id = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?
        .id
        .to_string();
    let uri = format!("/api/v2/sbom/{id}/all-license-ids");
    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    let expected_result = json!([
      {
        "license_id": "(APACHE-2.0 OR EPL-2.0)",
        "license_name": "(APACHE-2.0 OR EPL-2.0)"
      },
      {
        "license_id": "(EPL-2.0 OR APACHE-2.0)",
        "license_name": "(EPL-2.0 OR APACHE-2.0)"
      },
      {
        "license_id": "APACHE-2.0 OR EPL-1.0",
        "license_name": "APACHE-2.0 OR EPL-1.0"
      },
      {
        "license_id": "APACHE-2.0 OR EPL-2.0",
        "license_name": "APACHE-2.0 OR EPL-2.0"
      },
      {
        "license_id": "Apache-2.0",
        "license_name": "Apache-2.0"
      },
      {
        "license_id": "BOUNCY-CASTLE-LICENCE",
        "license_name": "BOUNCY-CASTLE-LICENCE"
      },
      {
        "license_id": "BSD-2-Clause",
        "license_name": "BSD-2-Clause"
      },
      {
        "license_id": "BSD-3-Clause",
        "license_name": "BSD-3-Clause"
      },
      {
        "license_id": "BSD-4-CLAUSE",
        "license_name": "BSD-4-CLAUSE"
      },
      {
        "license_id": "CC0-1.0",
        "license_name": "CC0-1.0"
      },
      {
        "license_id": "CC0-1.0 OR BSD-2-CLAUSE",
        "license_name": "CC0-1.0 OR BSD-2-CLAUSE"
      },
      {
        "license_id": "EPL-1.0",
        "license_name": "EPL-1.0"
      },
      {
        "license_id": "EPL-2.0",
        "license_name": "EPL-2.0"
      },
      {
        "license_id": "EPL-2.0 OR BSD-3-CLAUSE",
        "license_name": "EPL-2.0 OR BSD-3-CLAUSE"
      },
      {
        "license_id": "EPL-2.0 OR GPL-2.0-WITH-CLASSPATH-EXCEPTION",
        "license_name": "EPL-2.0 OR GPL-2.0-WITH-CLASSPATH-EXCEPTION"
      },
      {
        "license_id": "EPL-2.0 OR GPL-2.0-WITH-CLASSPATH-EXCEPTION OR BSD-3-CLAUSE",
        "license_name": "EPL-2.0 OR GPL-2.0-WITH-CLASSPATH-EXCEPTION OR BSD-3-CLAUSE"
      },
      {
        "license_id": "GNU-LESSER-GENERAL-PUBLIC-LICENSE OR APACHE-2.0",
        "license_name": "GNU-LESSER-GENERAL-PUBLIC-LICENSE OR APACHE-2.0"
      },
      {
        "license_id": "LGPL-2.1",
        "license_name": "LGPL-2.1"
      },
      {
        "license_id": "LGPL-2.1+",
        "license_name": "LGPL-2.1+"
      },
      {
        "license_id": "LGPL-2.1-ONLY OR EPL-1.0",
        "license_name": "LGPL-2.1-ONLY OR EPL-1.0"
      },
      {
        "license_id": "LGPL-2.1-OR-LATER",
        "license_name": "LGPL-2.1-OR-LATER"
      },
      {
        "license_id": "LGPL-2.1-only",
        "license_name": "LGPL-2.1-only"
      },
      {
        "license_id": "MIT",
        "license_name": "MIT"
      },
      {
        "license_id": "MPL-1.1 OR LGPL-2.1-ONLY OR APACHE-2.0",
        "license_name": "MPL-1.1 OR LGPL-2.1-ONLY OR APACHE-2.0"
      },
      {
        "license_id": "MPL-2.0 OR EPL-1.0",
        "license_name": "MPL-2.0 OR EPL-1.0"
      },
      {
        "license_id": "NOASSERTION",
        "license_name": "NOASSERTION"
      },
      {
        "license_id": "PUBLIC-DOMAIN",
        "license_name": "PUBLIC-DOMAIN"
      },
      {
        "license_id": "SIMILAR-TO-APACHE-LICENSE-BUT WITH THE-ACKNOWLEDGMENT-CLAUSE-REMOVED",
        "license_name": "SIMILAR-TO-APACHE-LICENSE-BUT WITH THE-ACKNOWLEDGMENT-CLAUSE-REMOVED"
      },
      {
        "license_id": "UPL-1.0",
        "license_name": "UPL-1.0"
      }
    ]);
    log::debug!("{}", serde_json::to_string_pretty(&response)?);
    assert!(expected_result.contains_subset(response.clone()));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_packages_sbom_by_query(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?
        .id
        .to_string();

    async fn query_value(app: &impl CallService, id: &str, q: &str) -> Value {
        let uri = format!("/api/v2/sbom/{id}/packages?q={}", urlencoding::encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }

    let result: Value = query_value(&app, &id, "name~logback-core").await;
    let expected_result = json!({
        "items": [
            {
                "id": "pkg:maven/ch.qos.logback/logback-core@1.2.13?type=jar",
                "name": "logback-core",
                "group": null,
                "version": "1.2.13",
                "purl": [
                    {
                        "uuid": "d09e1b8f-493c-5bf2-9bf9-e2b2bfe03c65",
                        "purl": "pkg:maven/ch.qos.logback/logback-core@1.2.13?type=jar",
                        "base": {
                            "uuid": "0bf904de-68cb-5c1b-910d-2fdc905dca4c",
                            "purl": "pkg:maven/ch.qos.logback/logback-core"
                        },
                        "version": {
                            "uuid": "35ebe249-9e92-58ea-b99c-70f451533bd7",
                            "purl": "pkg:maven/ch.qos.logback/logback-core@1.2.13",
                            "version": "1.2.13"
                        },
                        "qualifiers": {
                            "type": "jar"
                        }
                    }
                ],
                "cpe": [],
                "licenses": [
                    {"license_type": "declared", "license_name": "EPL-1.0"},
                    {"license_type": "declared", "license_name": "GNU Lesser General Public License"}
                ],
                "licenses_ref_mapping": []
            }
        ],
        "total": 1
    });

    assert!(result.contains_subset(expected_result));
    let result: Value = query_value(&app, &id, "name~logback-cor&Text~EPL").await;
    let expected_result = json!({
        "items": [
            {
                "id": "pkg:maven/ch.qos.logback/logback-core@1.2.13?type=jar",
                "name": "logback-core",
                "group": null,
                "version": "1.2.13",
                "purl": [
                    {
                        "uuid": "d09e1b8f-493c-5bf2-9bf9-e2b2bfe03c65",
                        "purl": "pkg:maven/ch.qos.logback/logback-core@1.2.13?type=jar",
                        "base": {
                            "uuid": "0bf904de-68cb-5c1b-910d-2fdc905dca4c",
                            "purl": "pkg:maven/ch.qos.logback/logback-core"
                        },
                        "version": {
                            "uuid": "35ebe249-9e92-58ea-b99c-70f451533bd7",
                            "purl": "pkg:maven/ch.qos.logback/logback-core@1.2.13",
                            "version": "1.2.13"
                        },
                        "qualifiers": {
                            "type": "jar"
                        }
                    }
                ],
                "cpe": [],
                "licenses": [
                    {"license_type": "declared", "license_name": "EPL-1.0"}
                ],
                "licenses_ref_mapping": []
            }
        ],
        "total": 1
    });
    assert!(result.contains_subset(expected_result));

    let id = ctx
        .ingest_document("spdx/SATELLITE-6.15-RHEL-8.json")
        .await?
        .id
        .to_string();

    let result = query_value(&app, &id, "name=rubygem-coffee-script").await;
    let expected_result = json!({
        "items": [
            {
                "id": "SPDXRef-02be9b35-a6ca-47b5-9c9e-9098c00ae212",
                "name": "rubygem-coffee-script",
                "group": null,
                "version": "2.4.1-5.el8sat",
                "purl": [
                    {
                        "uuid": "2ecff62f-9726-50fc-84b6-d191df754b21",
                        "purl": "pkg:rpm/redhat/rubygem-coffee-script@2.4.1-5.el8sat?arch=noarch",
                        "base": {
                            "uuid": "4b2847bd-1178-5394-9cda-7c0c5229eaba",
                            "purl": "pkg:rpm/redhat/rubygem-coffee-script"
                        },
                        "version": {
                            "uuid": "b39cd776-c23d-597f-a2e6-4d49f8216e1e",
                            "purl": "pkg:rpm/redhat/rubygem-coffee-script@2.4.1-5.el8sat",
                            "version": "2.4.1-5.el8sat"
                        },
                        "qualifiers": {
                            "arch": "noarch"
                        }
                    }
                ],
                "cpe": [],
                "licenses": [
                    {"license_type": "declared", "license_name": "MIT"},
                    {"license_type": "concluded", "license_name": "MIT"}
                ],
                "licenses_ref_mapping": []
            },
            {
                "id": "SPDXRef-9fe51d0d-aec8-4a70-9bf0-70b60606632d",
                "name": "rubygem-coffee-script",
                "group": null,
                "version": "2.4.1-5.el8sat",
                "purl": [
                    {
                        "uuid": "ebfe4205-23c4-56b3-8c94-473bfe70cc81",
                        "purl": "pkg:rpm/redhat/rubygem-coffee-script@2.4.1-5.el8sat?arch=src",
                        "base": {
                            "uuid": "4b2847bd-1178-5394-9cda-7c0c5229eaba",
                            "purl": "pkg:rpm/redhat/rubygem-coffee-script"
                        },
                        "version": {
                            "uuid": "b39cd776-c23d-597f-a2e6-4d49f8216e1e",
                            "purl": "pkg:rpm/redhat/rubygem-coffee-script@2.4.1-5.el8sat",
                            "version": "2.4.1-5.el8sat"
                        },
                        "qualifiers": {
                            "arch": "src"
                        }
                    }
                ],
                "cpe": [
                    "cpe:/a:redhat:satellite:6.15:*:el8:*",
                    "cpe:/a:redhat:satellite:6.11:*:el8:*",
                    "cpe:/a:redhat:satellite:6.14:*:el8:*",
                    "cpe:/a:redhat:satellite:6.12:*:el8:*",
                    "cpe:/a:redhat:satellite:6.13:*:el8:*"
                ],
                "licenses": [
                    {"license_type": "declared", "license_name": "MIT"},
                    {"license_type": "concluded", "license_name": "MIT"}
                ],
                "licenses_ref_mapping": []
            }
        ],
        "total": 2
    });
    assert!(result.contains_subset(expected_result));

    // Multiple LicenseRefs license expression
    let result = query_value(&app, &id, "name=foreman-bootloaders-redhat").await;
    let expected_result = json!({
      "items": [
        {
          "id": "SPDXRef-2a02a923-8a04-489d-9cbc-80f2d23de5ea",
          "name": "foreman-bootloaders-redhat",
          "group": null,
          "version": "202102220000-1.el8sat",
          "purl": [
            {
              "uuid": "7cd96c1d-391c-5e34-94be-ff48e5ae6b8c",
              "purl": "pkg:rpm/redhat/foreman-bootloaders-redhat@202102220000-1.el8sat?arch=src",
              "base": {
                "uuid": "2294dff1-103b-5cfc-9095-0c9c52e48445",
                "purl": "pkg:rpm/redhat/foreman-bootloaders-redhat"
              },
              "version": {
                "uuid": "a2257c48-57fa-52cb-8ac8-a721706cffaf",
                "purl": "pkg:rpm/redhat/foreman-bootloaders-redhat@202102220000-1.el8sat",
                "version": "202102220000-1.el8sat"
              },
              "qualifiers": {
                "arch": "src"
              }
            }
          ],
          "cpe": [
            "cpe:/a:redhat:satellite:6.15:*:el8:*",
            "cpe:/a:redhat:satellite_capsule:6.14:*:el8:*",
            "cpe:/a:redhat:satellite_capsule:6.13:*:el8:*",
            "cpe:/a:redhat:satellite_capsule:6.15:*:el8:*",
            "cpe:/a:redhat:satellite_capsule:6.12:*:el8:*",
            "cpe:/a:redhat:satellite:6.14:*:el8:*",
            "cpe:/a:redhat:satellite:6.12:*:el8:*",
            "cpe:/a:redhat:satellite:6.13:*:el8:*"
          ],
          "licenses": [
            {
              "license_name": "GPLv2+ AND GPLv3+ AND BSD",
              "license_type": "declared"
            },
            {
              "license_name": "NOASSERTION",
              "license_type": "concluded"
            }
          ],
          "licenses_ref_mapping": []
        },
        {
          "id": "SPDXRef-bad734a4-0235-478e-a95b-b20c48aa39a8",
          "name": "foreman-bootloaders-redhat",
          "group": null,
          "version": "202102220000-1.el8sat",
          "purl": [
            {
              "uuid": "610503a6-668b-5f02-9b11-435ee099bf61",
              "purl": "pkg:rpm/redhat/foreman-bootloaders-redhat@202102220000-1.el8sat?arch=noarch",
              "base": {
                "uuid": "2294dff1-103b-5cfc-9095-0c9c52e48445",
                "purl": "pkg:rpm/redhat/foreman-bootloaders-redhat"
              },
              "version": {
                "uuid": "a2257c48-57fa-52cb-8ac8-a721706cffaf",
                "purl": "pkg:rpm/redhat/foreman-bootloaders-redhat@202102220000-1.el8sat",
                "version": "202102220000-1.el8sat"
              },
              "qualifiers": {
                "arch": "noarch"
              }
            }
          ],
          "cpe": [],
          "licenses": [
            {
              "license_name": "GPLv2+ AND GPLv3+ AND BSD",
              "license_type": "declared"
            },
            {
              "license_name": "NOASSERTION",
              "license_type": "concluded"
            }
          ],
          "licenses_ref_mapping": []
        }
      ],
      "total": 2
    });
    assert!(result.contains_subset(expected_result));

    // Mixed License ID and LicenseRef license expression
    let result = query_value(&app, &id, "name=rubygem-apipie-rails").await;
    let expected_result = json!({
      "items": [
        {
          "id": "SPDXRef-2ac8cdfc-cb74-498e-90b7-cd9455736bc4",
          "name": "rubygem-apipie-rails",
          "group": null,
          "version": "1.2.3-1.el8sat",
          "purl": [
            {
              "uuid": "7aaa8d16-64c9-595d-94d0-9764ced4c6f4",
              "purl": "pkg:rpm/redhat/rubygem-apipie-rails@1.2.3-1.el8sat?arch=src",
              "base": {
                "uuid": "297c9bf5-4347-51e7-965f-5d084765157c",
                "purl": "pkg:rpm/redhat/rubygem-apipie-rails"
              },
              "version": {
                "uuid": "49f2973d-23fe-531e-8180-84065a0b1db2",
                "purl": "pkg:rpm/redhat/rubygem-apipie-rails@1.2.3-1.el8sat",
                "version": "1.2.3-1.el8sat"
              },
              "qualifiers": {
                "arch": "src"
              }
            }
          ],
          "cpe": [
            "cpe:/a:redhat:satellite:6.15:*:el8:*"
          ],
          "licenses": [
            {
              "license_name": "MIT AND ASL 2.0",
              "license_type": "declared"
            },
            {
              "license_name": "NOASSERTION",
              "license_type": "concluded"
            }
          ],
          "licenses_ref_mapping": []
        },
        {
          "id": "SPDXRef-ddce7aa4-9b82-42a5-bbc7-355d963ca2d8",
          "name": "rubygem-apipie-rails",
          "group": null,
          "version": "1.2.3-1.el8sat",
          "purl": [
            {
              "uuid": "abeef7ab-361c-5234-a27d-d016114dd3d5",
              "purl": "pkg:rpm/redhat/rubygem-apipie-rails@1.2.3-1.el8sat?arch=noarch",
              "base": {
                "uuid": "297c9bf5-4347-51e7-965f-5d084765157c",
                "purl": "pkg:rpm/redhat/rubygem-apipie-rails"
              },
              "version": {
                "uuid": "49f2973d-23fe-531e-8180-84065a0b1db2",
                "purl": "pkg:rpm/redhat/rubygem-apipie-rails@1.2.3-1.el8sat",
                "version": "1.2.3-1.el8sat"
              },
              "qualifiers": {
                "arch": "noarch"
              }
            }
          ],
          "cpe": [],
          "licenses": [
            {
              "license_name": "NOASSERTION",
              "license_type": "declared"
            },
            {
              "license_name": "NOASSERTION",
              "license_type": "concluded"
            }
          ],
          "licenses_ref_mapping": []
        }
      ],
      "total": 2
    });
    assert!(result.contains_subset(expected_result));

    // License ID only as license
    let result = query_value(&app, &id, "name=python-diff-match-patch").await;
    let expected_result = json!({
      "items": [
        {
          "id": "SPDXRef-2e34eff2-f039-4446-bf45-8e81e2c78346",
          "name": "python-diff-match-patch",
          "group": null,
          "version": "20200713-6.el8pc",
          "purl": [
            {
              "uuid": "97714c37-dd46-52dc-accb-73dc8084a10f",
              "purl": "pkg:rpm/redhat/python-diff-match-patch@20200713-6.el8pc?arch=src",
              "base": {
                "uuid": "246bc41b-3238-532d-8b82-db071dd33d3a",
                "purl": "pkg:rpm/redhat/python-diff-match-patch"
              },
              "version": {
                "uuid": "974a26ca-c417-55d9-8a5b-16adca100c53",
                "purl": "pkg:rpm/redhat/python-diff-match-patch@20200713-6.el8pc",
                "version": "20200713-6.el8pc"
              },
              "qualifiers": {
                "arch": "src"
              }
            }
          ],
          "cpe": [
            "cpe:/a:redhat:satellite:6.15:*:el8:*",
            "cpe:/a:redhat:satellite_capsule:6.15:*:el8:*"
          ],
          "licenses": [
            {
              "license_name": "Apache-2.0",
              "license_type": "declared"
            },
            {
              "license_name": "NOASSERTION",
              "license_type": "concluded"
            }
          ],
          "licenses_ref_mapping": []
        }
      ],
      "total": 1
    });
    assert!(result.contains_subset(expected_result));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn license_export(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("cyclonedx/application.cdx.json")
        .await?
        .id
        .to_string();

    let uri = format!("/api/v2/sbom/{id}/license-export");
    let req = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(req).await;

    assert!(response.status().is_success());
    let content_type = response
        .headers()
        .get("Content-Type")
        .expect("Content-Type header missing");
    assert_eq!(content_type, "application/gzip");

    let body = actix_web::test::read_body(response).await;
    let mut decoder = GzDecoder::new(&body[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)?;

    assert!(decompressed.contains("spring-petclinic_license_ref.csv"));
    assert!(decompressed.contains("spring-petclinic_sbom_licenses.csv"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let request = TestRequest::post()
        .uri("/api/v2/sbom")
        .set_payload(document_bytes("quarkus-bom-2.13.8.Final-redhat-00004.json").await?)
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);
    let result: IngestResult = actix_web::test::read_body_json(response).await;
    log::debug!("ID: {result:?}");
    assert!(matches!(result.id, Id::Uuid(_)));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("spdx/quarkus-bom-3.2.11.Final-redhat-00001.json")
        .await?
        .id
        .to_string();
    let uri = format!("/api/v2/sbom/{id}");
    let req = TestRequest::get().uri(&uri).to_request();
    let sbom: Value = app.call_and_read_body_json(req).await;
    log::debug!("{sbom:#?}");

    // assert expected fields
    assert_eq!(sbom["id"], id);
    assert_eq!(sbom["number_of_packages"], 1053);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn filter_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?
        .id
        .to_string();

    async fn query(app: &impl CallService, id: &str, q: &str) -> PaginatedResults<SbomPackage> {
        let uri = format!("/api/v2/sbom/{id}/packages?q={}", encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }

    let result = query(&app, &id, "").await;
    assert_eq!(result.total, 41);

    let result = query(&app, &id, "netty-common").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].name, "netty-common");

    let result = query(&app, &id, r"type\=jar").await;
    assert_eq!(result.total, 41);

    let result = query(&app, &id, "version=4.1.105.Final").await;
    assert_eq!(result.total, 9);

    let result = query(&app, &id, "license=Apache-2.0").await;
    assert_eq!(result.total, 35);

    let result = query(&app, &id, "license~GNU Lesser General Public License").await;
    assert_eq!(result.total, 2);

    let result = query(
        &app,
        &id,
        "license~Apache-2.0|GNU Lesser General Public License",
    )
    .await;
    assert_eq!(result.total, 37);

    let result = query(
        &app,
        &id,
        "license~EPL-1.0|GNU Lesser General Public License",
    )
    .await;
    assert_eq!(result.total, 10);

    Ok(())
}

/// Test updating labels
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn update_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::test::label::update_labels(
        ctx,
        Api::Sbom,
        "quarkus-bom-2.13.8.Final-redhat-00004.json",
        "spdx",
    )
    .await
}

/// Test updating labels, for a document that does not exist
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn update_labels_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::test::label::update_labels_not_found(
        ctx,
        Api::Sbom,
        "quarkus-bom-2.13.8.Final-redhat-00004.json",
    )
    .await
}

/// Test deleting an sbom
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let storage = &ctx.storage;
    let result = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    let key = StorageKey::try_from(Id::from_str(
        "sha256:488c5d97daed3613746f0c246f4a3d1b26ea52ce43d6bdd33f4219f881a00c07",
    )?)?;
    assert!(storage.retrieve(key.clone()).await?.is_some());

    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v2/sbom/{}", result.id.clone()))
                .to_request(),
        )
        .await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);
    assert!(storage.retrieve(key).await?.is_none());

    // We get the old sbom back when a delete succeeds
    let doc: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(doc["id"], result.id.to_string().as_ref());

    // If we try again, we should get a 404 since it was deleted.
    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v2/sbom/{}", result.id.clone()))
                .to_request(),
        )
        .await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

/// Test fetching an sbom
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn download_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const FILE: &str = "quarkus-bom-2.13.8.Final-redhat-00004.json";
    let app = caller(ctx).await?;
    let bytes = document_bytes(FILE).await?;
    let result = ctx.ingest_document(FILE).await?;
    let id = result.id.to_string();

    let req = TestRequest::get()
        .uri(&format!("/api/v2/sbom/{id}"))
        .to_request();

    let sbom = app.call_and_read_body_json::<SbomSummary>(req).await;
    assert_eq!(Id::Uuid(sbom.head.id), result.id);

    let doc = sbom.source_document;

    let hashes = vec![doc.sha256, doc.sha384, doc.sha512];

    // Verify we can download by all hashes
    for hash in hashes {
        let req = TestRequest::get()
            .uri(&format!("/api/v2/sbom/{hash}/download"))
            .to_request();
        let body = app.call_and_read_body(req).await;
        assert_eq!(bytes, body);
    }

    // Verify we can download by uuid
    let req = TestRequest::get()
        .uri(&format!("/api/v2/sbom/{id}/download"))
        .to_request();
    let body = app.call_and_read_body(req).await;
    assert_eq!(bytes, body);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let id = ctx
        .ingest_documents([
            "quarkus-bom-2.13.8.Final-redhat-00004.json",
            "csaf/cve-2023-0044.json",
        ])
        .await?[0]
        .id
        .to_string();

    let app = caller(ctx).await?;
    let v: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("/api/v2/sbom/{id}/advisory"))
                .to_request(),
        )
        .await;

    log::debug!("{v:#?}");

    // assert expected fields
    assert_eq!(v[0]["identifier"], "https://www.redhat.com/#CVE-2023-0044");
    assert_eq!(v[0]["status"][0]["average_severity"], "medium");
    assert_eq!(v[0]["status"][0]["scores"][0]["type"], "3.1");
    assert_eq!(v[0]["status"][0]["scores"][0]["value"], 5.3);
    assert_eq!(v[0]["status"][0]["scores"][0]["severity"], "medium");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_advisories_with_deprecated_filtering(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let id = ctx
        .ingest_documents([
            "quarkus-bom-2.13.8.Final-redhat-00004.json",
            "cve/CVE-2024-26308.json",
            // "cve/CVE-2024-26308-updated.json",
        ])
        .await?[0]
        .id
        .to_string();

    let app = caller(ctx).await?;
    let v: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("/api/v2/sbom/{id}/advisory"))
                .to_request(),
        )
        .await;

    log::debug!("{v:#?}");

    // assert expected fields
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["identifier"], "CVE-2024-26308");
    assert_eq!(v[0]["status"][0]["average_severity"], "none");
    assert!(v[0]["status"][0]["scores"].as_array().unwrap().is_empty());

    ctx.ingest_documents(["cve/CVE-2024-26308-updated.json"])
        .await?;

    let v: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("/api/v2/sbom/{id}/advisory"))
                .to_request(),
        )
        .await;

    // Should only return 1 advisory (the updated, non-deprecated version)
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["identifier"], "CVE-2024-26308");
    // The updated version has CVSS scores, unlike the original
    assert_eq!(v[0]["status"][0]["average_severity"], "medium");
    assert_eq!(v[0]["status"][0]["scores"][0]["type"], "3.1");
    assert_eq!(v[0]["status"][0]["scores"][0]["value"], 5.5);
    assert_eq!(v[0]["status"][0]["scores"][0]["severity"], "medium");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_sboms_by_ingested_time(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    async fn query(app: &impl CallService, q: &str) -> Value {
        let uri = format!(
            "/api/v2/sbom?q={}&sort={}",
            urlencoding::encode(q),
            urlencoding::encode("ingested:desc")
        );
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }
    let app = caller(ctx).await?;

    // Ingest 2 sbom's, capturing the time between each ingestion
    ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;
    let t = chrono::Local::now().to_rfc3339();
    ctx.ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    let all = query(&app, "ingested>yesterday").await;
    let ubi = query(&app, &format!("ingested<{t}")).await;
    let zoo = query(&app, &format!("ingested>{t}")).await;

    log::debug!("{all:#?}");

    // assert expected fields
    assert_eq!(all["total"], 2);
    assert_eq!(all["items"][0]["name"], json!("zookeeper"));
    assert_eq!(all["items"][1]["name"], json!("ubi9-container"));
    assert_eq!(ubi["total"], 1);
    assert_eq!(ubi["items"][0]["name"], json!("ubi9-container"));
    assert_eq!(zoo["total"], 1);
    assert_eq!(zoo["items"][0]["name"], json!("zookeeper"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_sboms_by_label(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let query = async |total, q| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v2/sbom?q={}", encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(req).await;
        assert_eq!(total, response["total"], "for {q}");
    };
    ctx.ingest_document_as(
        "zookeeper-3.9.2-cyclonedx.json",
        Format::CycloneDX,
        [
            ("type", "cyclonedx"),
            ("source", "test"),
            ("importer", "none"),
            ("file", "zoo.json"),
            ("datasetFile", "none"),
            ("foo", "bar"),
            ("pfx/app.first-name", "jim"),
        ],
    )
    .await?;
    ctx.ingest_document_as(
        "spdx/openssl-3.0.7-18.el9_2.spdx.json",
        Format::SPDX,
        [
            ("type", "spdx"),
            ("source", "test"),
            ("importer", "some"),
            ("file", "openssl.json"),
            ("datasetFile", "zilch"),
            ("foo", "baz"),
            ("pfx/app.first-name", "carlos"),
        ],
    )
    .await?;

    query(0, "labels:type=spdx&labels:type=cyclonedx").await;
    query(0, "labels:type!=spdx&labels:type!=cyclonedx").await;
    query(0, "labels:type!=spdx|cyclonedx").await;
    query(2, "labels:type=spdx|cyclonedx").await;
    query(1, "labels:type!=spdx").await;
    query(1, "labels:type~clone").await;
    query(1, "labels:type=cyclonedx").await;
    query(1, "labels:type=cyclonedx&labels:source=test").await;
    query(
        1,
        "labels:type=cyclonedx&labels:source=test&labels:importer=none",
    )
    .await;
    query(
        1,
        "labels:type=cyclonedx&labels:source=test&labels:importer=none&labels:file=zoo.json",
    )
    .await;
    query(1, "labels:type=cyclonedx&labels:source=test&labels:importer=none&labels:file=zoo.json&labels:datasetFile=none").await;
    query(2, "labels:file>foo.json").await;
    query(1, "labels:file>poo.json").await;
    query(1, "labels:datasetFile<zilch").await;
    query(1, "label:foo=bar").await;
    query(1, "label:type=cyclonedx").await;
    query(2, "label:importer=some|none").await;
    query(1, "label:type!=spdx").await;
    query(1, "labels:type~one&labels:foo>aah").await;
    query(1, "labels:importer~one&label:file~zoo").await;
    query(2, "labels:pfx/app.first-name=carlos|jim").await;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_sboms_by_package(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let query = async |purl, sort| {
        let app = caller(ctx).await.unwrap();
        let uri = format!(
            "/api/v2/sbom/by-package?purl={}&sort={}",
            encode(purl),
            encode(sort)
        );
        let request = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        tracing::debug!(test = "", "{response:#?}");
        response
    };

    // Ingest 2 SBOM's that depend on the same purl
    ctx.ingest_documents(["spdx/simple-ext-a.json", "spdx/simple-ext-b.json"])
        .await?;

    assert_eq!(
        2,
        query("pkg:rpm/redhat/A@0.0.0?arch=src", "").await["total"]
    );
    assert_eq!(
        "simple-a",
        query("pkg:rpm/redhat/A@0.0.0?arch=src", "name:asc").await["items"][0]["name"]
    );
    assert_eq!(
        "simple-b",
        query("pkg:rpm/redhat/A@0.0.0?arch=src", "name:desc").await["items"][0]["name"]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_sboms_by_array_values(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "quarkus-bom-2.13.8.Final-redhat-00004.json",
        "spdx/rhelai1_binary.json",
    ])
    .await?;

    let query = async |expected_count, q| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v2/sbom?q={}", encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(req).await;
        tracing::debug!(test = "", "{response:#?}");
        assert_eq!(expected_count, response["total"], "for {q}");
    };

    query(1, "authors~syft").await;
    query(1, "authors~Product").await;
    query(2, "authors~Product|Tool").await;
    query(1, "suppliers~Red Hat&authors~Red Hat").await;
    query(1, "suppliers=Organization: Red Hat").await;
    query(1, "suppliers!=Organization: Red Hat&authors~syft").await;
    query(0, "authors<ZZZ").await;
    query(2, "authors>ZZZ").await;
    query(2, "organization").await;
    query(1, "tool: syft").await;

    Ok(())
}

async fn test_label(
    ctx: &TrustifyContext,
    query: &str,
    limit: impl Into<Option<u64>>,
    result: Value,
) -> anyhow::Result<()> {
    let app = caller(ctx).await.unwrap();

    let _id = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?
        .id
        .to_string();

    let mut uri = format!("/api/v2/sbom-labels?filter_text={}", encode(query));

    if let Some(limit) = limit.into() {
        uri.push_str(&format!("&limit={limit}"));
    }

    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    tracing::debug!(test = "", "{response:#?}");

    assert_eq!(response, result,);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_label(
        ctx,
        "",
        None,
        json!([
            { "key": "source", "value": "TrustifyContext"},
            { "key": "type", "value": "spdx"}
        ]),
    )
    .await?;

    test_label(
        ctx,
        "spdx",
        None,
        json!([
            { "key": "type", "value": "spdx"}
        ]),
    )
    .await?;

    test_label(
        ctx,
        "pd",
        None,
        json!([
            { "key": "type", "value": "spdx"}
        ]),
    )
    .await?;

    test_label(
        ctx,
        "yp",
        None,
        json!([
            { "key": "type", "value": "spdx"}
        ]),
    )
    .await?;

    test_label(ctx, "%", None, json!([])).await?;

    test_label(
        ctx,
        "",
        1u64,
        json!([
            { "key": "source", "value": "TrustifyContext"},
        ]),
    )
    .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_cbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("cyclonedx/cryptographic/cbom.json")
        .await?
        .id
        .to_string();
    let uri = format!("/api/v2/sbom/{id}");
    let req = TestRequest::get().uri(&uri).to_request();
    let sbom: Value = app.call_and_read_body_json(req).await;
    log::debug!("{sbom:#?}");

    // assert expected fields
    assert_eq!(sbom["id"], id);
    assert_eq!(
        sbom["document_id"],
        "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79/1"
    );
    assert_eq!(sbom["number_of_packages"], 3);
    let labels = sbom["labels"].as_object().unwrap();
    assert_eq!(labels["kind"], "cbom");
    assert_eq!(labels["type"], "cyclonedx");

    let uri = format!("/api/v2/sbom/{id}/packages");
    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    log::info!("{:#}", json!(response));
    let expected_result = json!({
    "items": [
      {
        "id": "acme-application",
        "name": "Acme Application",
        "group": null,
        "version": "1.0",
        "purl": [],
        "cpe": [],
        "licenses": [],
        "licenses_ref_mapping": []
      },
      {
        "id": "crypto-library",
        "name": "Crypto library",
        "group": null,
        "version": "1.0.0",
        "purl": [],
        "cpe": [],
        "licenses": [],
        "licenses_ref_mapping": []
      },
      {
        "id": "some-library",
        "name": "Some library",
        "group": null,
        "version": "1.0.0",
        "purl": [],
        "cpe": [],
        "licenses": [],
        "licenses_ref_mapping": []
      }
    ],
    "total": 3 });
    assert!(expected_result.contains_subset(response.clone()));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_aibom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("cyclonedx/ai/ibm-granite_granite-docling-258M_aibom.json")
        .await?
        .id
        .to_string();
    let uri = format!("/api/v2/sbom/{id}");
    let req = TestRequest::get().uri(&uri).to_request();
    let sbom: Value = app.call_and_read_body_json(req).await;
    log::debug!("{sbom:#?}");

    // assert expected fields
    assert_eq!(sbom["id"], id);
    assert_eq!(sbom["number_of_packages"], 1);
    let labels = sbom["labels"].as_object().unwrap();
    assert_eq!(labels["kind"], "aibom");
    assert_eq!(labels["type"], "cyclonedx");

    let uri = format!("/api/v2/sbom/{id}/packages");
    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    log::info!("{:#}", json!(response));
    let expected_result = json!(
          {
           "items": [
        {
          "id": "pkg:generic/ibm-granite%2Fgranite-docling-258M@1.0",
          "name": "granite-docling-258M",
          "group": null,
          "version": "1.0",
          "purl": [
            {
              "uuid": "b3d8c434-ec9c-592a-91c8-596183beb691",
              "purl": "pkg:generic/ibm-granite/granite-docling-258M@1.0",
              "base": {
                "uuid": "c28a16be-ec3a-5289-a37c-769330a32905",
                "purl": "pkg:generic/ibm-granite/granite-docling-258M"
              },
              "version": {
                "uuid": "b3d8c434-ec9c-592a-91c8-596183beb691",
                "purl": "pkg:generic/ibm-granite/granite-docling-258M@1.0",
                "version": "1.0"
              },
              "qualifiers": {}
            }
          ],
          "cpe": [],
          "licenses": [],
          "licenses_ref_mapping": []
        },
      ],
      "total": 1
    }
          );
    assert!(expected_result.contains_subset(response.clone()));
    Ok(())
}
