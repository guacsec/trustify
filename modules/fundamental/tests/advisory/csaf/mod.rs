#![allow(clippy::expect_used)]

mod delete;
mod parallel;
mod reingest;
mod timeout;

use std::str::FromStr;

use csaf_rs::schema::csaf2_0::schema::{
    CommonSecurityAdvisoryFramework as Csaf, ProductIdT, ProductsT, Revision, SummaryOfTheRevision,
    VersionT,
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
    let current = &csaf.document.tracking.version;

    let next = uptick_version(current).expect("unable to increment version");
    let next = VersionT::from_str(&next).expect("upticked version is valid");

    csaf.document.tracking.version = next.clone();
    csaf.document.tracking.revision_history.push(Revision {
        date: Default::default(),
        legacy_version: None,
        number: next,
        summary: SummaryOfTheRevision::from_str("Updated for test").expect("test summary is valid"),
    });
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
            let vulns = &mut csaf.vulnerabilities;
            assert!(!vulns.is_empty(), "test data has vulnerabilities");

            let v = vulns
                .iter_mut()
                .find(|v| v.cve.as_ref().is_some_and(|cve| **cve == CVE))
                .expect("test data has a specific CVE");

            let ps = v
                .product_status
                .as_mut()
                .expect("test data has product status information");

            // remove from fixed to known affected

            let mut fixed = ps
                .fixed
                .as_ref()
                .expect(r#"test data has "fixed" entries"#)
                .to_vec();
            fixed.retain(|ps| ps.as_str() != PRODUCT);
            ps.fixed = Some(fixed.into());

            let mut known_affected = ps
                .known_affected
                .as_ref()
                .expect(r#"test data has "known affected" entries"#)
                .to_vec();
            known_affected.push(ProductIdT::from_str(PRODUCT).expect("test product id is valid"));
            ps.known_affected = Some(ProductsT(known_affected));

            csaf
        },
        |mut csaf| {
            uptick_tracking(&mut csaf);
            let mut date = trustify_module_ingestor::service::advisory::csaf::loader::parse_date(
                &csaf.document.tracking.current_release_date,
            )
            .expect("test date is valid");
            date += chrono::Duration::days(1);
            csaf.document.tracking.current_release_date = date.to_rfc3339();

            let vulns = &mut csaf.vulnerabilities;
            assert!(!vulns.is_empty(), "test data has vulnerabilities");

            let v = vulns
                .iter_mut()
                .find(|v| v.cve.as_ref().is_some_and(|cve| **cve == CVE))
                .expect("test data has a specific CVE");

            let ps = v
                .product_status
                .as_mut()
                .expect("test data has product status information");

            // now back to fixed

            // ProductT is missing implementation of DerefMut
            let mut known_affected = ps
                .known_affected
                .as_ref()
                .expect(r#"test data has "known affected" entries"#)
                .to_vec();
            known_affected.retain(|ps| ps.as_str() != PRODUCT);
            ps.known_affected = Some(known_affected.into());

            let mut fixed = ps
                .fixed
                .as_ref()
                .expect(r#"test data has "fixed" entries"#)
                .to_vec();
            fixed.push(ProductIdT::from_str(PRODUCT).expect("test product id is valid"));
            ps.fixed = Some(ProductsT(fixed));

            csaf
        },
    )
    .await
}
