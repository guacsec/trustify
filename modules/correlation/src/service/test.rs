use crate::model::{
    CorrelationState, PackageCatalog, PurlKey, PurlStatusEntry, SbomPackageEntry, VersionRangeData,
};
use std::collections::HashMap;
use std::sync::Arc;
use trustify_entity::version_scheme::VersionScheme;
use uuid::Uuid;

#[test]
fn correlate_basic_match() {
    let advisory_id = Uuid::new_v4();
    let status_id = Uuid::new_v4();
    let sbom_id = Uuid::new_v4();

    let purl_key = PurlKey {
        ty: Arc::from("maven"),
        namespace: Some(Arc::from("org.example")),
        name: Arc::from("test-pkg"),
    };

    let pkg = SbomPackageEntry {
        ty: Arc::from("maven"),
        version: Arc::from("1.5.0"),
        name: Arc::from("test-pkg"),
        namespace: Some(Arc::from("org.example")),
    };
    let catalog = PackageCatalog::from_entries(vec![pkg]);

    let state = CorrelationState {
        advisory_index: crate::model::AdvisoryIndex {
            by_purl: HashMap::from([(
                purl_key.clone(),
                vec![PurlStatusEntry {
                    advisory_id,
                    vulnerability_id: Arc::from("CVE-2024-0001"),
                    status_id,
                    version_range: VersionRangeData {
                        version_scheme: VersionScheme::Semver,
                        low_parsed: lenient_semver::parse("1.0.0").ok(),
                        high_parsed: lenient_semver::parse("2.0.0").ok(),
                        low_version: Some(Arc::from("1.0.0")),
                        low_inclusive: true,
                        high_version: Some(Arc::from("2.0.0")),
                        high_inclusive: false,
                    },
                    context_cpe_id: None,
                }],
            )]),
            product_by_name: HashMap::new(),
            statuses: HashMap::from([(status_id, Arc::from("affected"))]),
        },
        sbom_index: crate::model::SbomIndex {
            catalog,
            by_sbom: HashMap::from([(sbom_id, Arc::from(vec![0u32].into_boxed_slice()))]),
            describing_cpes: HashMap::new(),
        },
    };

    // Test using the version_matches directly
    let pkg = state
        .sbom_index
        .catalog
        .get(state.sbom_index.by_sbom[&sbom_id][0]);
    let entry = &state.advisory_index.by_purl[&purl_key][0];
    assert!(crate::model::version::version_matches(
        &pkg.version,
        &entry.version_range
    ));
}
