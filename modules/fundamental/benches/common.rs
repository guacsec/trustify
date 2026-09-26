#![allow(clippy::unwrap_used, clippy::expect_used)]

use test_context::AsyncTestContext;
use tokio::runtime::Runtime;
use trustify_test_context::{TrustifyContext, document};

use bytes::Bytes;
use cpe::cpe::Cpe;
use cpe::uri::OwnedUri;
use csaf_rs::schema::csaf2_0::schema::{
    BranchesT, CommonPlatformEnumerationRepresentation, CommonSecurityAdvisoryFramework as Csaf,
    Cve, HelperToIdentifyTheProduct as ProductIdentificationHelper, PackageUrlRepresentation,
    ProductTree, TitleOfThisDocument, UniqueIdentifierForTheDocument, Vulnerability,
};
use packageurl::PackageUrl;
use std::io::Error;
use std::rc::Rc;
use uuid::Uuid;

use std::str::FromStr;

use sea_orm::ConnectionTrait;

pub fn setup_runtime_and_ctx() -> (Runtime, Rc<TrustifyContext>) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let ctx = runtime.block_on(async { TrustifyContext::setup().await });
    (runtime, Rc::new(ctx))
}

pub async fn document_generated_from(path: &str, rev: u64) -> Result<Bytes, Error> {
    let (mut doc, _): (Csaf, _) = document(path).await.expect("load ok");
    doc.document.tracking.id = UniqueIdentifierForTheDocument::from_str(&format!(
        "{}-{rev}",
        doc.document.tracking.id.as_str(),
    ))
    .unwrap();

    fn rev_branches(branches: &mut Option<BranchesT>, rev: u64) {
        if let Some(BranchesT(branches)) = branches {
            for branch in branches.iter_mut() {
                if let Some(product) = &mut branch.product {
                    rev_product_helper(&mut product.product_identification_helper, rev);
                }
                rev_branches(&mut branch.branches, rev);
            }
        }
    }

    fn rev_product_helper(helper: &mut Option<ProductIdentificationHelper>, rev: u64) {
        if let Some(helper) = helper {
            if let Some(cpe) = &mut helper.cpe {
                let cpe = OwnedUri::from_str(cpe.as_str()).unwrap();
                let cpe = rev_cpe(&cpe, rev);
                helper.cpe = Some(
                    CommonPlatformEnumerationRepresentation::from_str(&cpe.to_string()).unwrap(),
                )
            }
            if let Some(purl) = &mut helper.purl {
                let purl = PackageUrl::from_str(purl.as_str()).unwrap();
                let purl = rev_purl(purl, rev);
                helper.purl = Some(PackageUrlRepresentation::from_str(&purl.to_string()).unwrap());
            }
        }
    }

    fn rev_purl(from: PackageUrl, rev: u64) -> PackageUrl {
        let name = from.name();
        let new_name = format!("{name}-{rev}");
        PackageUrl::from_str(
            from.to_string()
                .replacen(name, new_name.as_str(), 1)
                .as_str(),
        )
        .unwrap()
    }
    fn rev_cpe(cpe: &OwnedUri, rev: u64) -> OwnedUri {
        let uri = format!("{cpe:0}");
        let mut uri = cpe::uri::Uri::parse(uri.as_str()).unwrap();
        let x = format!("{}_{}", uri.product(), rev);
        uri.set_product(x.as_str()).unwrap();
        uri.to_owned()
    }
    fn rev_product_tree(product_tree: &mut ProductTree, rev: u64) {
        rev_branches(&mut product_tree.branches, rev);
        for relationship in product_tree.relationships.iter_mut() {
            // rev_product_id(&mut relationship.full_product_name.product_id, rev);
            rev_product_helper(
                &mut relationship.full_product_name.product_identification_helper,
                rev,
            );
        }
    }
    fn rev_vulnerability(vulnerability: &mut Vulnerability, rev: u64) {
        for cve in vulnerability.cve.iter_mut() {
            *cve = Cve::from_str(&format!("{}-{rev}", cve.as_str())).unwrap();
        }
    }

    for product_tree in doc.product_tree.iter_mut() {
        rev_product_tree(product_tree, rev);
    }
    for vulnerability in doc.vulnerabilities.iter_mut() {
        rev_vulnerability(vulnerability, rev);
    }

    //NOTE: Generating a random title to make the bench pass avoiding `document vanished` error.
    let uuid = Uuid::new_v4();
    doc.document.title =
        TitleOfThisDocument::from_str(&format!("random_title-{rev}-{uuid}")).unwrap();

    let data = serde_json::to_vec_pretty(&doc).expect("serialize ok");
    Ok(Bytes::from(data))
}

pub async fn reset_db(ctx: &Rc<TrustifyContext>) {
    // reset DB tables to a clean state...
    for table in [
        "advisory",
        "base_purl",
        "versioned_purl",
        "qualified_purl",
        "cvss3",
        "cpe",
        "version_range",
        "vulnerability",
    ] {
        ctx.db
            .execute_unprepared(format!("DELETE FROM {table}").as_str())
            .await
            .expect("DELETE ok");
    }
    ctx.db
        .execute_unprepared("VACUUM ANALYZE")
        .await
        .expect("vacuum analyze ok");
}
