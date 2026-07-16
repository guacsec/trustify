use crate::model::{CorrelationState, PurlStatusEntry, SbomPackageEntry, VersionRangeData};
use std::collections::{HashMap, HashSet};
use trustify_entity::version_scheme::VersionScheme;
use uuid::Uuid;

#[test]
fn correlate_basic_match() {
    let advisory_id = Uuid::new_v4();
    let base_purl_id = Uuid::new_v4();
    let status_id = Uuid::new_v4();
    let sbom_id = Uuid::new_v4();

    let state = CorrelationState {
        advisory_index: crate::model::AdvisoryIndex {
            by_base_purl: HashMap::from([(
                base_purl_id,
                vec![PurlStatusEntry {
                    advisory_id,
                    vulnerability_id: "CVE-2024-0001".to_string(),
                    status_id,
                    version_range: VersionRangeData {
                        version_scheme: VersionScheme::Semver,
                        low_version: Some("1.0.0".to_string()),
                        low_inclusive: true,
                        high_version: Some("2.0.0".to_string()),
                        high_inclusive: false,
                    },
                    context_cpe_id: None,
                }],
            )]),
            product_by_name: HashMap::new(),
            statuses: HashMap::from([(status_id, "affected".to_string())]),
            deprecated_advisories: HashSet::new(),
        },
        sbom_index: crate::model::SbomIndex {
            by_sbom: HashMap::from([(
                sbom_id,
                vec![SbomPackageEntry {
                    base_purl_id,
                    version: "1.5.0".to_string(),
                    name: "test-pkg".to_string(),
                    namespace: None,
                }],
            )]),
            describing_cpes: HashMap::new(),
        },
    };

    // Test using the version_matches directly
    let pkg = &state.sbom_index.by_sbom[&sbom_id][0];
    let entry = &state.advisory_index.by_base_purl[&base_purl_id][0];
    assert!(crate::model::version::version_matches(
        &pkg.version,
        &entry.version_range
    ));
}
