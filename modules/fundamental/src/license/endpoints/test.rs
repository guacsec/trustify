use crate::license::model::{SpdxLicenseDetails, SpdxLicenseSummary};
use crate::license::service::LicenseText;
use crate::test::caller;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_common::model::PaginatedResults;
use trustify_test_context::{TrustifyContext, call::CallService};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_spdx_licenses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v2/license/spdx/license?total=true";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<SpdxLicenseSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(Some(734), response.total);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_spdx_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v2/license/spdx/license/GLWTPL";
    let request = TestRequest::get().uri(uri).to_request();
    let response: SpdxLicenseDetails = app.call_and_read_body_json(request).await;
    assert_eq!(response.summary.id, "GLWTPL");

    let uri = "/api/v2/license/spdx/license/GlwtPL";
    let request = TestRequest::get().uri(uri).to_request();
    let response: SpdxLicenseDetails = app.call_and_read_body_json(request).await;
    assert_eq!(response.summary.id, "GLWTPL");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_no_data(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v2/license?total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    // Should have the preloaded licenses from DB init when no SBOMs are loaded
    assert_eq!(response.items.len(), 25);
    assert_eq!(response.total, Some(652));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_with_spdx_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Ingest an SPDX SBOM that has LicenseRef mappings
    ctx.ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;

    let uri = "/api/v2/license?sort=license:asc&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.items.len(), 25); // 25 is the default for pagination
    assert_eq!(response.total, Some(732));

    // Check that we have some expected licenses from the SPDX SBOM
    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();

    // Basic checks for licenses that should be in this SPDX SBOM
    assert!(license_names.iter().any(|l| l.contains("ASL 2.0"))); // Apache Software License 2.0
    assert!(license_names.iter().any(|l| l.contains("BSD"))); // BSD licenses
    assert!(license_names.iter().any(|l| l.contains("MIT"))); // MIT license
    // Expended license for LicenseRef-13
    assert!(license_names.iter().any(|l| l.contains(
        "(FTL or GPLv2+) and BSD and MIT and Public Domain and zlib with acknowledgement"
    )));
    // Expanded license from (LicenseRef-4 OR LicenseRef-Artistic) AND LicenseRef-5 AND LicenseRef-UCD
    assert!(
        license_names
            .iter()
            .any(|l| l.contains("(GPL+ OR Artistic) AND Artistic 2.0 AND UCD"))
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_no_license_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Ingest an SPDX SBOM that has LicenseRef mappings
    ctx.ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;

    let uri = "/api/v2/license?sort=license:asc&limit=733&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.items.len(), 732);
    assert_eq!(response.total, Some(732));

    // Check that we have some expected licenses from the SPDX SBOM
    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();

    // Verify that we don't have raw LicenseRef- values in the output
    // (they should all be expanded to their actual license names)
    let license_ref_found = license_names
        .into_iter()
        .filter(|l| l.contains("LicenseRef-"))
        .collect::<Vec<String>>();
    assert_eq!(
        license_ref_found.len(),
        0,
        "No 'LicenseRef-' should exist but {:?} have been found",
        license_ref_found
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_with_cyclonedx_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Ingest a CycloneDX SBOM
    ctx.ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    let uri = "/api/v2/license?sort=license:asc&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.items.len(), 25);
    assert_eq!(response.total, Some(659));

    // Check that we have some expected licenses from the CycloneDX SBOM
    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();

    assert!(
        license_names
            .iter()
            .any(|l| l.contains("(CDDL-1.0 OR GPL-2.0-with-classpath-exception)"))
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_with_mixed_sboms(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Ingest both SPDX and CycloneDX SBOMs
    ctx.ingest_documents([
        "spdx/OCP-TOOLS-4.11-RHEL-8.json",
        "zookeeper-3.9.2-cyclonedx.json",
    ])
    .await?;

    let uri = "/api/v2/license?sort=license:asc&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(736));
    assert_eq!(response.items.len(), 25);

    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();

    // Should have licenses from both SPDX and CycloneDX
    assert!(
        license_names
            .iter()
            .any(|l| l.contains("(GPL+ OR Artistic) AND Artistic 2.0 AND UCD"))
    ); // Expanded license from (LicenseRef-4 OR LicenseRef-Artistic) AND LicenseRef-5 AND LicenseRef-UCD
    assert!(
        license_names
            .iter()
            .any(|l| l.contains("(CDDL-1.0 OR GPL-2.0-with-classpath-exception)"))
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_with_search_filter(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Ingest SBOMs with various licenses
    ctx.ingest_documents([
        "spdx/OCP-TOOLS-4.11-RHEL-8.json",
        "zookeeper-3.9.2-cyclonedx.json",
    ])
    .await?;

    // Test search filter for "ASL" (Apache Software License)
    let uri = "/api/v2/license?q=license~ASL&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(4));

    // Test full text search filter for "ASL" (Apache Software License)
    let uri = "/api/v2/license?q=ASL&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(4));

    // Test case-insensitive search filter for "asl"
    let uri = "/api/v2/license?q=asl&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(4));

    // Test case-insensitive search filter for "AsL"
    let uri = "/api/v2/license?q=AsL&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(4));

    // Test for non-existent license
    let uri = "/api/v2/license?q=NonExistentLicense&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(Some(0), response.total);
    assert_eq!(0, response.items.len());

    // Test search filter for "ASL" (Apache Software License) and sorting (default asc)
    let uri = "/api/v2/license?q=license~ASL&sort=license&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(4));
    // Verify licenses are sorted in ascending order
    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();
    let mut sorted_licenses = license_names.clone();
    sorted_licenses.sort();
    assert_eq!(license_names, sorted_licenses);

    // Test full text search filter for "ASL" (Apache Software License) and sorting desc
    let uri = "/api/v2/license?q=ASL&sort=license:desc&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(4));
    // Verify licenses are sorted in descending order
    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();
    let mut sorted_licenses = license_names.clone();
    sorted_licenses.sort();
    sorted_licenses.reverse();
    assert_eq!(license_names, sorted_licenses);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_with_pagination(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Test pagination - first page
    let uri = "/api/v2/license?limit=5&offset=0&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    let total_licenses = response.total.expect("total should be present");
    assert!(total_licenses > 0);

    if total_licenses > 5 {
        assert_eq!(5, response.items.len());
    } else {
        assert_eq!(total_licenses as usize, response.items.len());
    }

    // Test pagination - second page (if there are enough items)
    if total_licenses > 5 {
        let uri = "/api/v2/license?limit=5&offset=5&total=true";
        let request = TestRequest::get().uri(uri).to_request();
        let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

        assert_eq!(Some(total_licenses), response.total); // Total should remain the same

        if total_licenses > 10 {
            assert_eq!(5, response.items.len());
        } else {
            assert_eq!((total_licenses - 5) as usize, response.items.len());
        }
    }

    // Test pagination with offset beyond available items
    let uri = format!(
        "/api/v2/license?limit=5&offset={}&total=true",
        total_licenses + 10
    );
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(Some(total_licenses), response.total); // Total should remain the same
    assert_eq!(0, response.items.len()); // No items should be returned

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_no_partial_license_ref_match(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Ingest an SPDX SBOM with overlapping LicenseRef- identifiers:
    // LicenseRef-BSD ("BSD License") vs LicenseRef-BSD-with-advertising ("BSD with advertising License")
    // LicenseRef-GPL ("GPL License") vs LicenseRef-GPLv2 ("GPLv2 License")
    ctx.ingest_document("spdx/license-ref-overlap.json").await?;

    let uri = "/api/v2/license?limit=1000";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();

    // The bug: LicenseRef-BSD matches within LicenseRef-BSD-with-advertising,
    // producing "BSD License-with-advertising" instead of "BSD with advertising License"
    assert!(
        !license_names
            .iter()
            .any(|l| l.contains("BSD License-with-advertising")),
        "Partial LicenseRef- match detected: 'BSD License-with-advertising' should not exist"
    );

    // Correct expansion of the full LicenseRef-BSD-with-advertising
    assert!(
        license_names
            .iter()
            .any(|l| l.contains("BSD with advertising License")),
        "Expected 'BSD with advertising License' from LicenseRef-BSD-with-advertising expansion"
    );

    // Short ref LicenseRef-BSD still works on its own
    assert!(
        license_names.iter().any(|l| l == "BSD License"),
        "Expected 'BSD License' from LicenseRef-BSD expansion"
    );

    // Both overlapping GPL refs expand correctly
    assert!(
        license_names
            .iter()
            .any(|l| l == "GPLv2 License OR GPL License"),
        "Expected 'GPLv2 License OR GPL License' from overlapping GPL LicenseRef expansion, found: {:?}",
        license_names
            .iter()
            .filter(|l| l.contains("GPL"))
            .collect::<Vec<_>>()
    );

    // No raw LicenseRef- values should remain
    let license_ref_found: Vec<&String> = license_names
        .iter()
        .filter(|l| l.contains("LicenseRef-"))
        .collect();
    assert!(
        license_ref_found.is_empty(),
        "No raw 'LicenseRef-' should remain but found: {:?}",
        license_ref_found
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses_sorting(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Ingest an SPDX SBOM that has LicenseRef mappings
    ctx.ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;

    let uri = "/api/v2/license?sort=license:asc&limit=733&total=true";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;

    assert_eq!(response.items.len(), 732);
    assert_eq!(response.total, Some(732));

    // Verify licenses are sorted
    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();
    let mut sorted_licenses = license_names.clone();
    sorted_licenses.sort();
    assert_eq!(license_names, sorted_licenses);

    let uri = "/api/v2/license?sort=license:desc&limit=733";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseText> = app.call_and_read_body_json(request).await;
    let license_names: Vec<String> = response.items.iter().map(|l| l.license.clone()).collect();
    sorted_licenses.reverse();
    assert_eq!(license_names, sorted_licenses);

    Ok(())
}
