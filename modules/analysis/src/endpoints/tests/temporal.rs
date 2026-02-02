use super::req::*;
use crate::test::{
    caller,
    data::{Phase, Set, Sources},
};
use rstest::*;
use std::collections::HashMap;
use test_context::test_context;
use trustify_test_context::{IngestionResult, TrustifyContext, q::escape_q};

/// Perform tests based on a dataset and a request.
///
/// * **Request:** The request towards the endpoint
/// * **Phase:** The phase the data is in (older, later)
/// * **Set:** The set (rpm, container, middleware)
/// * **Expected:** Expected set of sbom/node pairs. If a node is `""`, it's an anonymous node in the SBOM
#[test_context(TrustifyContext)]
#[rstest]
#[case( // cpe by id search, non-latest
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), ..Req::default() },
    [Phase::Older],
    [
        ("product-2025-11-25-D05BF995974542F.json", "RHEL-9-CNV-4.17"),
    ]
)]
#[case( // cpe by id search, non-latest
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), ..Req::default() },
    [Phase::Older, Phase::Later],
    [
        ("product-2025-11-25-D05BF995974542F.json", "RHEL-9-CNV-4.17"),
        ("product-2025-12-02-ED1F188BB5C94D8.json", "RHEL-9-CNV-4.17"),
    ]
)]
#[case( // cpe by id search
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), latest: true, ..Req::default() },
    [Phase::Older],
    [
        ("product-2025-11-25-D05BF995974542F.json", "RHEL-9-CNV-4.17"),
    ]
)]
#[case( // cpe by id search
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), latest: true, ..Req::default() },
    [Phase::Older, Phase::Later],
    [
        ("product-2025-12-02-ED1F188BB5C94D8.json", "RHEL-9-CNV-4.17"),
    ]
)]
#[case( // purl search
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), ..Req::default() },
    [Phase::Older],
    []
)]
#[case( // purl search
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), ..Req::default() },
    [Phase::Older, Phase::Later],
    [
        ("binary-2025-12-02-C0CF40B259B1491.json", ""),
        ("binary-2025-12-02-C0CF40B259B1491.json", "pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&tag=v4.17.36-3"),
        ("image-index-2025-12-02-693F980C32C444A.json", "virt-handler-rhel9-container_amd64"),
    ]
)]
#[case( // purl search, latest
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), latest: true, ..Req::default() },
    [Phase::Older],
    // it is missing here
    []
)]
#[case( // purl search, latest
    Req { what: What::Q(&format!("purl~{}", escape_q("pkg:oci/virt-handler-rhel9@sha256%3A507d126fa23811854bb17531194f9e832167022a1a30542561aadfd668bf1542?arch=amd64&os=linux&repository_url=registry.access.redhat.com%2Fcontainer-native-virtualization%2Fvirt-handler-rhel9&tag=v4.17.36-3"))), latest: true, ..Req::default() },
    [Phase::Older, Phase::Later],
    [
        ("image-index-2025-12-02-693F980C32C444A.json", "virt-handler-rhel9-container_amd64")
    ]
)]
#[test_log::test(actix_web::test)]
async fn container_evolve(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[values(&[Set::Container][..], &[Set::Container, Set::Rpm][..], &[Set::Container, Set::Rpm, Set::Middleware][..])]
    set: &[Set],
    #[case] phase: impl IntoIterator<Item = Phase>,
    #[case] expected: impl IntoIterator<Item = (&str, &str)>,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // materialize iterators

    let phase = Vec::from_iter(phase);
    let docs = Vec::from_iter(Sources(set.iter().copied(), phase));

    // ingest, and create a map of sbom id -> file name

    let sboms = ctx.ingest_documents(&docs).await?.collect_uuid_str();
    let sboms: HashMap<_, _> = sboms.into_iter().zip(docs).collect();
    log::info!("SBOMS: {sboms:#?}");

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let response = app.req(req).await?;

    log::info!("{response:#?}");

    // process result, extract sbom/node pairs

    let mut items = vec![];
    for item in response["items"].as_array().into_iter().flatten() {
        let sbom = item["sbom_id"].as_str().expect("SBOM ID must be a string");
        let node = item["node_id"].as_str().expect("Node ID must be a string");

        let sbom = sboms[sbom].as_str();

        items.push((sbom, node));
    }

    let expected = Vec::from_iter(expected);

    // check total number

    assert_eq!(expected.len(), response["total"]);

    // check if expected items match, node ID is equal. SBOM is the file, we only match the
    // trailing part

    assert!(
        items.iter().zip(&expected).all(
            |((item_sbom, item_node), (expected_sbom, expected_node))| {
                if item_node != expected_node && !expected_node.is_empty() {
                    // if the expectation is an empty string, then it's an empty node ID which
                    // got replaced with a generated UUID during ingestion.
                    return false;
                }

                item_sbom.ends_with(expected_sbom)
            }
        ),
        "Mismatch - expected: {expected:?}, actual: {items:?}"
    );

    // done

    Ok(())
}
