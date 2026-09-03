use crate::model::ExtractPackage;
use serde_cyclonedx::cyclonedx::v_1_6::{Component, ComponentEvidenceIdentity, CycloneDx};
use std::collections::BTreeMap;
use trustify_common::purl::Purl;

/// Extract PURLs from a SPDX file
pub fn extract_spdx_purls(
    sbom: spdx_rs::models::SPDX,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, ExtractPackage> {
    let mut result = BTreeMap::<String, ExtractPackage>::new();

    for pkg in sbom.package_information {
        let mut purls = vec![];
        for er in pkg.external_reference {
            if er.reference_type == "purl" {
                purls.extend(filter_purl(er.reference_locator, warnings));
            }
        }

        result
            .entry(pkg.package_name)
            .or_default()
            .purls
            .extend(purls)
    }

    result
}

/// Extract PURLs from a CycloneDX file
pub fn extract_cyclonedx_purls(
    sbom: CycloneDx,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, ExtractPackage> {
    let mut result = BTreeMap::new();

    fn scan_comps(
        result: &mut BTreeMap<String, ExtractPackage>,
        warnings: &mut Vec<String>,
        component: Component,
    ) {
        let mut purls = vec![];
        if let Some(purl) = component.purl.and_then(|purl| filter_purl(purl, warnings)) {
            purls.push(purl);
        }

        purls.extend(
            component
                .evidence
                .into_iter()
                .flat_map(|cev| cev.identity)
                .flat_map(|id| match id {
                    ComponentEvidenceIdentity::Variant0(id) => id,
                    ComponentEvidenceIdentity::Variant1(id) => vec![id],
                })
                .filter(|id| id.field == "purl")
                .flat_map(|id| id.concluded_value)
                .flat_map(|purl| filter_purl(purl, warnings)),
        );

        result
            .entry(component.name)
            .or_default()
            .purls
            .extend(purls);

        for comp in component.components.into_iter().flatten() {
            scan_comps(result, warnings, comp);
        }
    }

    if let Some(component) = sbom.metadata.and_then(|md| md.component) {
        scan_comps(&mut result, warnings, component);
    }

    for component in sbom.components.into_iter().flatten() {
        scan_comps(&mut result, warnings, component);
    }

    result
}

/// Filter out invalid PURLs
///
/// If the PURL is valid, return the `Some(input)`, otherwise return `None`.
fn filter_purl(purl: String, warnings: &mut Vec<String>) -> Option<String> {
    match Purl::try_from(purl.as_str()) {
        Ok(_) => Some(purl),
        Err(err) => {
            warnings.push(format!("failed to parse purl: {err}"));
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn assert(purl: &str, error: Option<&str>) {
        let mut warnings = vec![];
        let result = filter_purl(String::from(purl), &mut warnings);

        if let Some(error) = error {
            assert!(result.is_none());
            assert_eq!(warnings, vec![error.to_string()])
        } else {
            assert_eq!(result, Some(purl.into()));
            assert!(warnings.is_empty());
        }
    }

    #[test]
    fn invalid() {
        assert(
            "",
            Some("failed to parse purl: packageurl problem missing scheme"),
        );
        assert(
            "pkg:",
            Some("failed to parse purl: packageurl problem missing type"),
        );
    }

    #[test]
    fn valid() {
        assert("pkg:golang/archive/tar", None);
    }
}
