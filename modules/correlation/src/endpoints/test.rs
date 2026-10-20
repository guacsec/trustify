use actix_web::{
    App,
    test::{TestRequest, call_service},
};
use test_context::test_context;
use test_log::test;
use trustify_common::db::{ReadOnly, ReadWrite, pagination_cache::PaginationCache};
use trustify_test_context::TrustifyContext;
use utoipa_actix_web::AppExt;
use uuid::Uuid;

/// Configure the correlation endpoints on the test database.
fn configure(svc: &mut utoipa_actix_web::service_config::ServiceConfig, ctx: &TrustifyContext) {
    super::configure(
        svc,
        ReadOnly::new(ctx.db.clone()),
        ReadWrite::new(ctx.db.clone()),
        PaginationCache::for_test(),
    );
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn freshness_overview_and_refresh_permissions(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use actix_web::{HttpMessage, web};
    use trustify_auth::{
        authenticator::user::{UserDetails, UserInformation},
        authorizer::{Authorizer, AuthorizerConfig},
    };
    let id = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    let app = App::new()
        .app_data(web::Data::new(Authorizer::new(Some(
            AuthorizerConfig::default(),
        ))))
        .into_utoipa_app()
        .configure(|svc| configure(svc, ctx))
        .into_app();
    let app = actix_web::test::init_service(app).await;
    let reader = UserInformation::Authenticated(UserDetails {
        id: "reader".into(),
        permissions: vec!["read.advisory".into()],
    });
    let writer = UserInformation::Authenticated(UserDetails {
        id: "writer".into(),
        permissions: vec!["read.advisory".into(), "update.correlationOption".into()],
    });
    let req = TestRequest::get()
        .uri("/v3/correlation/freshness")
        .to_request();
    assert_eq!(call_service(&app, req).await.status(), 403);
    let req = TestRequest::get()
        .uri("/v3/correlation/freshness")
        .to_request();
    req.extensions_mut().insert(reader.clone());
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(body["unknown"], 1);
    assert_eq!(body["needs_refresh"], 1);
    let req = TestRequest::get()
        .uri("/v3/correlation/freshness/sbom?status=unknown&limit=1&total=true")
        .to_request();
    req.extensions_mut().insert(reader.clone());
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["sbom_id"], id.to_string());
    let req = TestRequest::post()
        .uri("/v3/correlation/refresh")
        .to_request();
    req.extensions_mut().insert(reader.clone());
    assert_eq!(call_service(&app, req).await.status(), 403);
    let req = TestRequest::post()
        .uri("/v3/correlation/refresh")
        .to_request();
    req.extensions_mut().insert(writer.clone());
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 202);
    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    let job_id = body["id"].as_str().unwrap();
    let req = TestRequest::post()
        .uri("/v3/correlation/refresh")
        .to_request();
    req.extensions_mut().insert(writer);
    let resp = call_service(&app, req).await;
    let again: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(again["id"], job_id);
    let req = TestRequest::get()
        .uri(&format!("/v3/correlation/refresh/{job_id}?limit=0"))
        .to_request();
    req.extensions_mut().insert(reader.clone());
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let details: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(details["job"]["id"], job_id);
    assert_eq!(details["failures"], serde_json::json!([]));
    let req = TestRequest::get()
        .uri(&format!("/v3/correlation/refresh/{}", Uuid::new_v4()))
        .to_request();
    req.extensions_mut().insert(reader);
    assert_eq!(call_service(&app, req).await.status(), 404);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn empty_sbom_returns_empty_verdicts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = App::new()
        .into_utoipa_app()
        .configure(|svc| {
            configure(svc, ctx);
        })
        .into_app();
    let app = actix_web::test::init_service(app).await;

    let id = Uuid::new_v4();
    let req = TestRequest::get()
        .uri(&format!("/v3/correlation/sbom/{id}"))
        .to_request();
    let resp = call_service(&app, req).await;

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(body["verdicts"], serde_json::json!([]));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_requires_kind(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = App::new()
        .into_utoipa_app()
        .configure(|svc| {
            configure(svc, ctx);
        })
        .into_app();
    let app = actix_web::test::init_service(app).await;

    let req = TestRequest::get()
        .uri("/v3/correlation/query?q=6925281924439")
        .to_request();
    assert_eq!(call_service(&app, req).await.status(), 400);

    let req = TestRequest::get()
        .uri("/v3/correlation/query?kind=sku&q=6925281924439")
        .to_request();
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(
        body,
        serde_json::json!({
            "query": { "kind": "sku", "value": "6925281924439" },
            "verdicts": [],
        })
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn verdict_counts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = App::new()
        .into_utoipa_app()
        .configure(|svc| {
            configure(svc, ctx);
        })
        .into_app();
    let app = actix_web::test::init_service(app).await;

    // unknown SBOMs get zero counts, in the requested order
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let req = TestRequest::post()
        .uri("/v3/correlation/verdict-counts")
        .set_json(serde_json::json!({ "sbom_ids": [a, b] }))
        .to_request();
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    let zero = |id: Uuid| {
        serde_json::json!({
            "sbom_id": id,
            "affected": 0,
            "fixed": 0,
            "not_affected": 0,
            "under_investigation": 0,
            "none": 0,
            "remediations": 0,
            "freshness": {"status":"unknown", "required_revision":1, "completed_revision":null, "completed_at":null},
        })
    };
    assert_eq!(body, serde_json::json!([zero(a), zero(b)]));

    // the number of SBOMs per request is limited
    let ids = (0..1001).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let req = TestRequest::post()
        .uri("/v3/correlation/verdict-counts")
        .set_json(serde_json::json!({ "sbom_ids": ids }))
        .to_request();
    assert_eq!(call_service(&app, req).await.status(), 400);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn aliases_and_read_only_context_preview(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use serde_json::{Value, json};
    use trustify_test_context::call::{CallService, caller};
    let app = caller(|svc| configure(svc, ctx)).await?;
    let base = "/api/v3/correlation";
    let response = app
        .call_service(
            TestRequest::post()
                .uri(&format!("{base}/provider-alias"))
                .set_json(json!({"provider":"A/","aliases":["name:Acme"]}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), 201);
    let alias: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(alias["provider"], "A");
    let id = alias["id"].as_str().unwrap();
    let response = app
        .call_service(
            TestRequest::post()
                .uri(&format!("{base}/provider-alias"))
                .set_json(json!({"provider":"B","aliases":["name:ACME"]}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), 409);
    let response = app
        .call_service(
            TestRequest::put()
                .uri(&format!("{base}/provider-alias/{id}"))
                .set_json(json!({"provider":"A","aliases":["name:Acme", "name:Acme Inc."]}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), 200);
    let updated: Value = actix_web::test::read_body_json(response).await;
    assert_ne!(updated["revision"], alias["revision"]);
    let before: Vec<Value> = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("{base}/provider-alias"))
                .to_request(),
        )
        .await;
    let target =
        json!({"kind":"identifier","identifier":{"kind":"purl","value":"pkg:generic/absent@1"}});
    let response = app.call_service(TestRequest::post()
        .uri(&format!("{base}/preview"))
        .set_json(json!({"target":target,"resolution":{"include_explanation":true,"component_provider":"A"}})).to_request()).await;
    assert_eq!(response.status(), 200);
    let after: Vec<Value> = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("{base}/provider-alias"))
                .to_request(),
        )
        .await;
    assert_eq!(before, after);
    assert!(after.contains(&updated));

    for resolution in [
        json!({"overrides":{"direct":0}}),
        json!({"group_id":Uuid::nil()}),
        json!({"weights":{}}),
        json!({"component_provider":" / "}),
        json!({"node_id":"node"}),
    ] {
        let response = app
            .call_service(
                TestRequest::post()
                    .uri(&format!("{base}/preview"))
                    .set_json(json!({"target":target,"resolution":resolution}))
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), 400);
    }
    for path in [
        format!("sbom/{}?group_id={}", Uuid::nil(), Uuid::nil()),
        "query?kind=purl&q=pkg:generic/absent@1&direct=2".into(),
    ] {
        let response = app
            .call_service(
                TestRequest::get()
                    .uri(&format!("{base}/{path}"))
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), 400);
    }
    for request in [
        TestRequest::get().uri(&format!("{base}/weight-policy")),
        TestRequest::post()
            .uri(&format!("{base}/weight-policy"))
            .set_json(json!({})),
        TestRequest::put()
            .uri(&format!("{base}/weight-policy/{}", Uuid::nil()))
            .set_json(json!({})),
        TestRequest::delete().uri(&format!("{base}/weight-policy/{}", Uuid::nil())),
    ] {
        assert_eq!(app.call_service(request.to_request()).await.status(), 404);
    }
    assert_eq!(
        app.call_service(
            TestRequest::delete()
                .uri(&format!("{base}/provider-alias/{id}"))
                .to_request()
        )
        .await
        .status(),
        204
    );
    let aliases: Vec<Value> = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("{base}/provider-alias"))
                .to_request(),
        )
        .await;
    assert!(!aliases.iter().any(|alias| alias["id"] == id));
    Ok(())
}

mod option {
    use super::configure;
    use crate::model::{CorrelationOption, CorrelationOptionData, CorrelationOptionKey};
    use actix_http::StatusCode;
    use actix_web::test::TestRequest;
    use serde_json::{Value, json};
    use test_context::test_context;
    use test_log::test;
    use trustify_common::model::PaginatedResults;
    use trustify_test_context::{
        TrustifyContext,
        call::{CallService, caller},
    };
    use uuid::Uuid;

    const BASE: &str = "/api/v3/correlation/option";

    fn data(publisher_namespace: &str, value: Value) -> CorrelationOptionData {
        CorrelationOptionData {
            key: CorrelationOptionKey::VersionlessPurl,
            publisher_namespace: publisher_namespace.into(),
            value,
            reason: Some("test".into()),
        }
    }

    /// The defaults are listed, ordered by publisher namespace.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn defaults(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let app = caller(|svc| configure(svc, ctx)).await?;

        let result: PaginatedResults<CorrelationOption> = app
            .call_and_read_body_json(TestRequest::get().uri(BASE).to_request())
            .await;

        assert_eq!(
            result
                .items
                .iter()
                .map(|option| (
                    option.data.key,
                    option.data.publisher_namespace.as_str(),
                    &option.data.value
                ))
                .collect::<Vec<_>>(),
            [
                (
                    CorrelationOptionKey::VersionlessPurl,
                    "https://www.redhat.com",
                    &json!(true)
                ),
                (
                    CorrelationOptionKey::VersionlessPurl,
                    "https://www.suse.com",
                    &json!(true)
                ),
                (
                    CorrelationOptionKey::FixedIsFirstFixed,
                    "https://www.redhat.com",
                    &json!(true)
                ),
            ]
        );

        Ok(())
    }

    /// Create, read, update and delete an option. The publisher namespace is stored without a
    /// trailing slash, and deleting is idempotent.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn crud(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let app = caller(|svc| configure(svc, ctx)).await?;

        // create

        let response = app
            .call_service(
                TestRequest::post()
                    .uri(BASE)
                    .set_json(data("https://example.com/", json!(true)))
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let created: Value = actix_web::test::read_body_json(response).await;
        let id: Uuid = serde_json::from_value(created["id"].clone())?;
        let uri = format!("{BASE}/{id}");

        let option: CorrelationOption = app
            .call_and_read_body_json(TestRequest::get().uri(&uri).to_request())
            .await;
        assert_eq!(
            option,
            CorrelationOption {
                id,
                data: data("https://example.com", json!(true)),
            }
        );

        // update

        let response = app
            .call_service(
                TestRequest::put()
                    .uri(&uri)
                    .set_json(data("https://example.com", json!(false)))
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let option: CorrelationOption = app
            .call_and_read_body_json(TestRequest::get().uri(&uri).to_request())
            .await;
        assert_eq!(option.data.value, json!(false));

        // delete, twice

        for _ in 0..2 {
            let response = app
                .call_service(TestRequest::delete().uri(&uri).to_request())
                .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        let response = app
            .call_service(TestRequest::get().uri(&uri).to_request())
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    /// Invalid requests: a duplicate, an unknown key, a value not fitting the key, and an update
    /// of an unknown option.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn invalid(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let app = caller(|svc| configure(svc, ctx)).await?;

        for (body, expected) in [
            // the default exists
            (
                serde_json::to_value(data("https://www.redhat.com/", json!(false)))?,
                StatusCode::CONFLICT,
            ),
            (
                json!({"key": "unknown", "publisher_namespace": "https://example.com", "value": true}),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::to_value(data("https://example.com", json!("yes")))?,
                StatusCode::BAD_REQUEST,
            ),
            (
                json!({"key": "fixed_is_first_fixed", "publisher_namespace": "https://example.com", "value": 1}),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::to_value(data("/", json!(true)))?,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = app
                .call_service(TestRequest::post().uri(BASE).set_json(&body).to_request())
                .await;
            assert_eq!(response.status(), expected, "{body}");
        }

        let response = app
            .call_service(
                TestRequest::put()
                    .uri(&format!("{BASE}/{}", Uuid::now_v7()))
                    .set_json(data("https://example.com", json!(true)))
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn advisory_statements(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use crate::model::{
        AdvisoryStatement, MatchedRange, RangeBound, StatementKind, StatementSubject,
    };
    use trustify_common::model::PaginatedResults;
    use trustify_test_context::call::{CallService, caller};

    let advisory = ctx.ingest_document("csaf/CVE-2024-34502.json").await?;
    let app = caller(|svc| configure(svc, ctx)).await?;

    let mut result = Vec::new();
    for kind in StatementKind::ALL {
        let statements: PaginatedResults<AdvisoryStatement> = app
            .call_and_read_body_json(
                TestRequest::get()
                    .uri(&format!(
                        "/api/v3/correlation/advisory/{}/statement?kind={}&vulnerability=CVE-2024-34502",
                        advisory.id,
                        kind.as_str()
                    ))
                    .to_request(),
            )
            .await;
        result.push((kind, statements));
    }

    let statement = |subject, range| AdvisoryStatement {
        vulnerability_id: "CVE-2024-34502".into(),
        status: "affected".into(),
        subject,
        range,
        default: false,
    };
    let bound = |version: &str, inclusive| {
        Some(RangeBound {
            version: version.into(),
            inclusive,
        })
    };

    assert_eq!(
        result,
        vec![
            (
                StatementKind::Purl,
                PaginatedResults {
                    items: vec![statement(
                        StatementSubject::Purl {
                            purl: "pkg:rpm/redhat/mediawiki?arch=src".into(),
                        },
                        // a versionless PURL is stored with an empty version
                        MatchedRange {
                            scheme: "generic".into(),
                            low: bound("", true),
                            high: bound("", true),
                        },
                    )],
                    total: None,
                }
            ),
            (
                StatementKind::Cpe,
                PaginatedResults {
                    items: vec![],
                    total: None,
                }
            ),
            (
                StatementKind::Product,
                PaginatedResults {
                    items: vec![statement(
                        StatementSubject::Product {
                            name: "Red Hat OpenShift Container Platform 3.11".into(),
                            cpe_key: Some("3.11".into()),
                            package: None,
                            csaf_product_ids: vec![
                                "red_hat_openshift_container_platform_3.11:mediawiki".into(),
                            ],
                        },
                        MatchedRange {
                            scheme: "rpm".into(),
                            low: bound("3.11.0", true),
                            high: bound("4.0.0", false),
                        },
                    )],
                    total: None,
                }
            ),
        ]
    );

    Ok(())
}

/// Ordinary reads and context previews expose the same explanation contract.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn explained_query_matches_preview(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use serde_json::{Value, json};
    use trustify_test_context::call::{CallService, caller};
    ctx.ingest_document("scenarios/S18_digest_correlation/vex/vde-2025-106.json")
        .await?;
    let app = caller(|svc| configure(svc, ctx)).await?;
    let base = "/api/v3/correlation";
    let digest = "sha256:d62b79b11e2ec822514b5b75fc7733e274b7efc722a3d099e10c4e1184dcf849";
    let ordinary: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("{base}/query?kind=digest&q={digest}"))
                .to_request(),
        )
        .await;
    let mut explained: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!(
                    "{base}/query?kind=digest&q={digest}&include_explanation=true"
                ))
                .to_request(),
        )
        .await;
    let preview: Value = app.call_and_read_body_json(TestRequest::post()
        .uri(&format!("{base}/preview"))
        .set_json(json!({"target":{"kind":"identifier","identifier":{"kind":"digest","value":digest}},"resolution":{"include_explanation":true}})).to_request()).await;
    assert_eq!(preview["result"], explained);
    let verdict = &mut explained["verdicts"][0];
    assert_eq!(verdict["status"], "fixed");
    assert_eq!(verdict["confidence"], 1.0);
    assert!(verdict.get("decision_weight").is_none());
    let trace = verdict
        .as_object_mut()
        .unwrap()
        .remove("explanation")
        .unwrap();
    assert!(trace.get("settings").is_none());
    assert!(trace.get("policy_revision").is_none());
    assert!(trace.get("confidence_penalty").is_none());
    assert!(trace["resolution_revision"].is_string());
    assert_eq!(trace["deciding_criterion"], "only_eligible_evidence");
    assert_eq!(trace["evidence"][0]["outcome"], "selected");
    assert_eq!(trace["evidence"][0]["match_confidence"], 1.0);
    assert!(trace["evidence"][0].get("weight").is_none());
    assert_eq!(ordinary, explained);
    Ok(())
}
