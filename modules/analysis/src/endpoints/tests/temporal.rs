use super::req::*;
use crate::test::{Join, caller, escape_q};
use rstest::*;
use test_context::test_context;
use trustify_test_context::TrustifyContext;

const BASE: &str = "cyclonedx/rh/latest_filters/TC-3278/";

mod container {

    use super::*;

    pub fn older() -> impl Iterator<Item = String> {
        BASE.join("container/cnv-4.17/older/".join(
            &[
                "binary-2025-11-25-3E72AAC00183431.json",
                "binary-2025-11-25-32EBB9C7E6914AD.json",
                "image-index-2025-11-25-CBE2989E64414F5.json",
                "product-2025-11-25-D05BF995974542F.json",
            ][..],
        ))
    }

    pub fn later() -> impl Iterator<Item = String> {
        BASE.join("container/cnv-4.17/latest/".join(
            &[
                "binary-2025-12-02-5C502A658F36477.json",
                "binary-2025-12-02-C0CF40B259B1491.json",
                "image-index-2025-12-02-693F980C32C444A.json",
                "product-2025-12-02-ED1F188BB5C94D8.json",
            ][..],
        ))
    }

    pub fn all() -> impl Iterator<Item = String> {
        older().chain(later())
    }
}

mod middleware {

    use super::*;

    pub fn older() -> impl Iterator<Item = String> {
        BASE.join(
            "middleware/quarkus-3.20/older/".join(&["product-2025-10-14-28954C62C811417.json"][..]),
        )
    }

    pub fn later() -> impl Iterator<Item = String> {
        BASE.join(
            "middleware/quarkus-3.20/latest/"
                .join(&["product-2025-12-01-EDA6638AD2F4451.json"][..]),
        )
    }

    #[allow(unused)]
    pub fn all() -> impl Iterator<Item = String> {
        older().chain(later())
    }
}

mod rpm {

    use super::*;

    pub fn older() -> impl Iterator<Item = String> {
        BASE.join("rpm/webkit2gtk3/older/".join(
            &[
                "product-2025-11-11-7764C2C0C91542B.json",
                "rpm-2025-10-14-CC595A02EB3545E.json",
            ][..],
        ))
    }

    pub fn later() -> impl Iterator<Item = String> {
        BASE.join("rpm/webkit2gtk3/latest/".join(
            &[
                "product-2025-12-08-A9F140D67EB2408.json",
                "rpm-2025-12-05-3705CE313B0F437.json",
            ][..],
        ))
    }

    #[allow(unused)]
    pub fn all() -> impl Iterator<Item = String> {
        older().chain(later())
    }
}

fn older() -> impl Iterator<Item = String> {
    container::older()
        .chain(middleware::older())
        .chain(rpm::older())
}

fn later() -> impl Iterator<Item = String> {
    container::later()
        .chain(middleware::later())
        .chain(rpm::later())
}

fn all() -> impl Iterator<Item = String> {
    older().chain(later())
}

/// Test how the responses change when first loading an older dataset, then the newer one.
#[test_context(TrustifyContext)]
#[rstest]
#[case( // cpe by id search, non-latest
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), ..Req::default() },
    container::older(), 1
)]
#[case( // cpe by id search, non-latest
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), ..Req::default() },
    container::all(), 2
)]
#[case( // cpe by id search
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), latest: true, ..Req::default() },
    container::older(), 1
)]
#[case( // cpe by id search
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), latest: true, ..Req::default() },
    container::all(), 1
)]
#[case( // purl search
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), ..Req::default() },
    container::older(), 0
)]
#[case( // purl search
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), ..Req::default() },
    container::all(), 3
)]
#[case( // purl search, latest
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), latest: true, ..Req::default() },
    container::older(), 0 // it is missing here, so zero
)]
#[case( // purl search, latest
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), latest: true, ..Req::default() },
    container::all(), 1 // FIXME: I'm not sure what to expect here, we had three matches, from three layers and now only one.
)]
#[test_log::test(actix_web::test)]
async fn container_evolve(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] docs: impl IntoIterator<Item = String>,
    #[case] total: usize,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(docs).await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let response = app.req(req).await?;

    log::info!("{response:#?}");
    assert_eq!(total, response["total"]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case( // cpe by id search, non-latest
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), ..Req::default() },
    older(), 1
)]
#[case( // cpe by id search, non-latest
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), ..Req::default() },
    all(), 2
)]
#[case( // cpe by id search
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), latest: true, ..Req::default() },
    older(), 1
)]
#[case( // cpe by id search
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), latest: true, ..Req::default() },
    all(), 1
)]
#[case( // purl search
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), ..Req::default() },
    older(), 0
)]
#[case( // purl search
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), ..Req::default() },
    all(), 3
)]
#[case( // purl search, latest
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), latest: true, ..Req::default() },
    older(), 0 // it is missing here, so zero
)]
#[case( // purl search, latest
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), latest: true, ..Req::default() },
    all(), 1 // FIXME: I'm not sure what to expect here, we had three matches, from three layers and now only one.
)]
#[test_log::test(actix_web::test)]
async fn all_evolve(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] docs: impl IntoIterator<Item = String>,
    #[case] total: usize,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(docs).await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let response = app.req(req).await?;

    log::info!("{response:#?}");
    assert_eq!(total, response["total"]);

    Ok(())
}
