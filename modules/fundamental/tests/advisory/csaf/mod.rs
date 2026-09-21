#![allow(clippy::expect_used)]

mod delete;
mod parallel;
mod reingest;
mod timeout;

use csaf::schema::csaf2_0::schema::{
    CommonSecurityAdvisoryFramework as Csaf, ProductIdT, Revision,
};
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::{TrustifyContext, document_bytes};

/// Ingest a document twice, mutating it using the provided closure.
async fn twice<M1, M2>(
    ctx: &TrustifyContext,
    m1: M1,
    m2: M2,
) -> anyhow::Result<(IngestResult, IngestResult)>
where
    M1: FnOnce(Csaf) -> Csaf,
    M2: FnOnce(Csaf) -> Csaf,
{
    let data = document_bytes("csaf/cve-2023-33201.json").await?;
    let csaf: Csaf = serde_json::from_slice(&data)?;

    let csaf = m1(csaf);

    let result = ctx
        .ingest_read(serde_json::to_vec(&csaf)?.as_slice())
        .await?;

    let csaf = m2(csaf);

    let result2 = ctx
        .ingest_read(serde_json::to_vec(&csaf)?.as_slice())
        .await?;

    Ok((result, result2))
}

/// Uptick the tracking information according to the spec, adding a new revision record,
/// incrementing the main tracking version.
fn uptick_tracking(csaf: &mut Csaf) {
    let current = csaf.document.tracking.version.as_str();

    let next = uptick_version(current).expect("unable to increment version");

    csaf.document.tracking.version = next.parse().expect("next version must be valid");
    csaf.document.tracking.revision_history.push(Revision {
        date: "1970-01-01T00:00:00Z".to_string(),
        legacy_version: None,
        number: next.parse().expect("next version must be valid"),
        summary: "Updated for test".parse().expect("summary must be valid"),
    });
}

/// Build a product ID, which is known to be valid.
fn product_id(id: &str) -> ProductIdT {
    id.parse().expect("product id must be valid")
}

/// Uptick the version by one.
///
/// The version can be either a plain number or a semantic version. We increment by one, considering
/// a major change.
///
/// > Whenever the operator needs to do a new matching run on his asset database (matching the products from the CSAF product tree with deployed products) the MAJOR version is incremented.
fn uptick_version(version: &str) -> anyhow::Result<String> {
    if version.contains('.') {
        let mut version = semver::Version::parse(version)?;
        version.major += 1;
        Ok(version.to_string())
    } else {
        let version = version.parse::<u64>()? + 1;
        Ok(version.to_string())
    }
}

/// prepare a state with an updated advisory, making a change in the product state section.
async fn prepare_ps_state_change(
    ctx: &TrustifyContext,
) -> anyhow::Result<(IngestResult, IngestResult)> {
    const CVE: &str = "CVE-2023-33201";
    const PRODUCT: &str =
        "9Base-JBEAP-7.4:eap7-bouncycastle-util-0:1.76.0-4.redhat_00001.1.el9eap.noarch";

    twice(
        ctx,
        |mut csaf| {
            let v = csaf
                .vulnerabilities
                .iter_mut()
                .find(|v| v.cve.as_ref().map(|cve| cve.as_str()) == Some(CVE))
                .expect("test data has a specific CVE");

            let ps = v
                .product_status
                .as_mut()
                .expect("test data has product status information");

            // remove from fixed to known affected

            ps.fixed
                .as_mut()
                .expect(r#"test data has "fixed" entries"#)
                .0
                .retain(|ps| ps.as_str() != PRODUCT);
            ps.known_affected
                .as_mut()
                .expect(r#"test data has "known affected" entries"#)
                .0
                .push(product_id(PRODUCT));

            csaf
        },
        |mut csaf| {
            uptick_tracking(&mut csaf);
            let next_release_date =
                chrono::DateTime::parse_from_rfc3339(&csaf.document.tracking.current_release_date)
                    .expect("test data has a valid release date")
                    + chrono::Duration::days(1);
            csaf.document.tracking.current_release_date = next_release_date.to_rfc3339();

            let v = csaf
                .vulnerabilities
                .iter_mut()
                .find(|v| v.cve.as_ref().map(|cve| cve.as_str()) == Some(CVE))
                .expect("test data has a specific CVE");

            let ps = v
                .product_status
                .as_mut()
                .expect("test data has product status information");

            // now back to fixed

            ps.known_affected
                .as_mut()
                .expect(r#"test data has "known affected" entries"#)
                .0
                .retain(|ps| ps.as_str() != PRODUCT);
            ps.fixed
                .as_mut()
                .expect(r#"test data has "fixed" entries"#)
                .0
                .push(product_id(PRODUCT));

            csaf
        },
    )
    .await
}
