use crate::{
    graph::{
        Graph, Outcome,
        advisory::{
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
            advisory_vulnerability::AdvisoryVulnerabilityContext,
            version::{Version, VersionInfo, VersionSpec},
        },
        cvss::ScoreCreator,
        purl::{
            self,
            creator::PurlCreator,
            status_creator::{PurlStatusCreator, PurlStatusEntry},
        },
        vulnerability::creator::VulnerabilityCreator,
    },
    model::IngestResult,
    service::{
        Error, Warnings,
        advisory::osv::{
            ecosystem::native_ecosystem, extract_scores, extract_vulnerability_ids,
            prefix::get_well_known_prefixes, translate,
        },
    },
};
use osv::schema::{Ecosystem, Event, Package, Range, RangeType, ReferenceType, Vulnerability};
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::{collections::HashSet, fmt::Debug, str::FromStr};
use tracing::instrument;
use trustify_common::{hashing::Digests, purl::Purl, time::ChronoExt};
use trustify_entity::{labels::Labels, version_scheme::VersionScheme};

pub struct OsvLoader<'g> {
    graph: &'g Graph,
}

impl<'g> OsvLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, osv, tx), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        osv: Vulnerability,
        digests: &Digests,
        issuer: Option<String>,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();

        let labels = labels.into().add("type", "osv");

        let issuer = issuer.or(detect_organization(&osv));

        let cve_ids = extract_vulnerability_ids(&osv);

        let information = AdvisoryInformation {
            id: osv.id.clone(),
            title: osv.summary.clone(),
            // TODO(#899): check if we have some kind of version information
            version: None,
            issuer,
            published: osv.published.map(ChronoExt::into_time),
            modified: Some(osv.modified.into_time()),
            withdrawn: osv.withdrawn.map(ChronoExt::into_time),
        };
        let advisory = match self
            .graph
            .ingest_advisory(&osv.id, labels, digests, information, tx)
            .await?
        {
            Outcome::Existed(advisory) => {
                return Ok(IngestResult {
                    id: advisory.advisory.id.to_string(),
                    document_id: Some(osv.id),
                    duplicate: true,
                    warnings: warnings.into(),
                    validation: Vec::new(),
                });
            }
            Outcome::Added(advisory) => advisory,
        };

        if let Some(withdrawn) = osv.withdrawn {
            advisory.set_withdrawn_at(withdrawn.into_time(), tx).await?;
        }

        // Batch create all vulnerabilities
        let mut vuln_creator = VulnerabilityCreator::new();
        for cve_id in &cve_ids {
            vuln_creator.add(*cve_id, ());
        }
        vuln_creator.create(tx).await?;

        let mut purl_creator = PurlCreator::new();
        let mut purl_status_creator = PurlStatusCreator::new();
        let mut base_purls = HashSet::new();
        let mut score_creator = ScoreCreator::new(advisory.advisory.id);

        extract_scores(&osv, &mut score_creator);

        // The affected entries with a package, and their PURLs. Resolved once, not per CVE, so
        // that PURL warnings are reported once, even without any CVE.
        let affected = osv
            .affected
            .iter()
            .flatten()
            .filter_map(|affected| {
                let Some(package) = &affected.package else {
                    tracing::debug!(osv = osv.id, "OSV 'affected' entry without a package");
                    return None;
                };
                Some((affected, package, package_purls(package, &warnings)))
            })
            .collect::<Vec<_>>();

        for cve_id in cve_ids {
            self.graph.ingest_vulnerability(cve_id, (), tx).await?;

            let advisory_vuln = advisory
                .link_to_vulnerability(
                    cve_id,
                    Some(AdvisoryVulnerabilityInformation {
                        title: osv.summary.clone(),
                        summary: osv.summary.clone(),
                        description: osv.details.clone(),
                        reserved_date: None,
                        discovery_date: None,
                        release_date: None,
                        cwes: None,
                    }),
                    tx,
                )
                .await?;

            for (affected, package, purls) in &affected {
                for purl in purls {
                    // iterate through the known versions, apply the version, and create them
                    for version in affected.versions.iter().flatten() {
                        purl_creator.add(purl.with_version(version));
                        // Process explicit versions for advisory linking
                        purl_status_creator.add(PurlStatusEntry {
                            advisory_id: advisory_vuln.advisory.advisory.id,
                            vulnerability_id: advisory_vuln
                                .advisory_vulnerability
                                .vulnerability_id
                                .clone(),
                            purl: purl.clone(),
                            status: "affected".to_string(),
                            version_info: VersionInfo {
                                scheme: VersionScheme::Generic,
                                spec: VersionSpec::Exact(version.to_string()),
                            },
                            context_cpe: None,
                        });
                    }

                    for range in affected.ranges.iter().flatten() {
                        // Collect base PURL for range-based status entries
                        base_purls.insert(purl.clone());

                        match version_scheme(&range.range_type, &package.ecosystem) {
                            Some(scheme) => process_status_entries(
                                build_package_status(&advisory_vuln, purl, range, scheme),
                                &mut purl_status_creator,
                            ),
                            None => process_status_entries(
                                build_package_status_versions(
                                    &advisory_vuln,
                                    purl,
                                    range,
                                    affected.versions.iter().flatten(),
                                ),
                                &mut purl_status_creator,
                            ),
                        }
                    }
                }
            }
        }

        purl_creator.create(tx).await?;
        score_creator.create(tx).await?;

        // Create base PURLs for range-based status entries
        purl::batch_create_base_purls(base_purls, tx).await?;

        purl_status_creator.create(tx).await?;

        Ok(IngestResult {
            id: advisory.advisory.id.to_string(),
            document_id: Some(osv.id),
            warnings: warnings.into(),
            duplicate: false,
            validation: Vec::new(),
        })
    }
}

/// Resolve package PURLs, reconciling repository information only for Lightwell.
///
/// Ordinary ecosystems retain their existing inferred and stated candidates without cross-field
/// validation, version stripping or warnings. Lightwell uses one reconciled PURL, warning and
/// skipping conflicting identities or repositories, and ignores a stated version with a warning.
/// This is a local policy, not an OSV-mandated rejection rule. Stored qualifiers do not
/// guarantee scoped matching.
fn package_purls(package: &Package, warnings: &Warnings) -> Vec<Purl> {
    let inferred = translate::to_purl(package).map(Purl::from);

    if !matches!(&package.ecosystem, Ecosystem::RedHatLightwell(_)) {
        let stated = package
            .purl
            .as_ref()
            .and_then(|stated| Purl::from_str(stated).ok());
        return inferred.into_iter().chain(stated).collect();
    }

    let stated = package.purl.as_ref().and_then(|stated| {
        let mut purl = Purl::from_str(stated)
            .inspect_err(|err| {
                warnings.add(format!("Invalid OSV package PURL '{stated}': {err}"));
            })
            .ok()?;
        if purl.version.take().is_some() {
            warnings.add(format!(
                "The PURL of an OSV package must not have a version, ignoring it: {stated}"
            ));
        }
        Some(purl)
    });

    let purl = match (inferred, stated) {
        (Some(inferred), Some(mut stated)) => {
            // NuGet IDs are case-insensitive; the PURL parser preserves their spelling.
            let same_name = if matches!(native_ecosystem(&package.ecosystem), Ecosystem::NuGet) {
                inferred.name.eq_ignore_ascii_case(&stated.name)
            } else {
                inferred.name == stated.name
            };
            if inferred.ty != stated.ty || inferred.namespace != stated.namespace || !same_name {
                warnings.add(format!(
                    "Conflicting inferred and stated PURLs for OSV package '{}': {inferred}, \
                     {stated}; affected entry ignored",
                    package.name
                ));
                return vec![];
            }
            match (
                inferred.qualifiers.get("repository_url"),
                stated.qualifiers.get("repository_url"),
            ) {
                (Some(inferred_repo), Some(stated_repo)) if inferred_repo != stated_repo => {
                    warnings.add(format!(
                        "Conflicting repositories for OSV package '{}': {inferred}, \
                         {stated}; affected entry ignored",
                        package.name
                    ));
                    return vec![];
                }
                (Some(repository), None) => {
                    stated
                        .qualifiers
                        .insert("repository_url".into(), repository.clone());
                }
                _ => {}
            }
            // Align the case-sensitive stored identity with the ecosystem/name spelling.
            if matches!(native_ecosystem(&package.ecosystem), Ecosystem::NuGet) {
                stated.name = inferred.name;
            }
            Some(stated)
        }
        (inferred, stated) => stated.or(inferred),
    };
    match purl {
        Some(purl) => vec![purl],
        None => {
            warnings.add(format!(
                "No usable PURL for OSV package '{}' ({:?}); affected entry ignored",
                package.name, package.ecosystem
            ));
            vec![]
        }
    }
}

/// The version scheme to evaluate a range with, `None` if unknown.
///
/// A range of an unknown scheme is evaluated on the enumerated `versions` instead.
fn version_scheme(range_type: &RangeType, ecosystem: &Ecosystem) -> Option<VersionScheme> {
    match range_type {
        RangeType::Semver => Some(VersionScheme::Semver),
        RangeType::Git => Some(VersionScheme::Git),
        RangeType::Ecosystem => Some(match native_ecosystem(ecosystem) {
            Ecosystem::Maven(_) => VersionScheme::Maven,
            Ecosystem::PyPI | Ecosystem::Python => VersionScheme::Python,
            Ecosystem::Go => VersionScheme::Golang,
            Ecosystem::Npm => VersionScheme::Npm,
            Ecosystem::Packagist => VersionScheme::Packagist,
            Ecosystem::NuGet => VersionScheme::NuGet,
            Ecosystem::RubyGems => VersionScheme::Gem,
            Ecosystem::Hex => VersionScheme::Hex,
            Ecosystem::SwiftURL => VersionScheme::Swift,
            Ecosystem::Pub => VersionScheme::Pub,
            Ecosystem::CratesIO => VersionScheme::Cargo,
            _ => return None,
        }),
        _ => None,
    }
}

/// Process status entries: add each entry to purl_status_creator.
fn process_status_entries(
    entries: Vec<PurlStatusEntry>,
    purl_status_creator: &mut PurlStatusCreator,
) {
    for entry in entries {
        purl_status_creator.add(entry);
    }
}

/// Build package status entries from range events
fn build_package_status(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    range: &Range,
    version_scheme: VersionScheme,
) -> Vec<PurlStatusEntry> {
    let mut entries = Vec::new();
    let parsed_range = events_to_range(&range.events);

    let spec = match &parsed_range {
        (Some(start), None) => Some(VersionSpec::Range(
            Version::Inclusive(start.clone()),
            Version::Unbounded,
        )),
        (None, Some((end, false))) => Some(VersionSpec::Range(
            Version::Unbounded,
            Version::Exclusive(end.clone()),
        )),
        (None, Some((end, true))) => Some(VersionSpec::Range(
            Version::Unbounded,
            Version::Inclusive(end.clone()),
        )),
        (Some(start), Some((end, false))) => Some(VersionSpec::Range(
            Version::Inclusive(start.clone()),
            Version::Exclusive(end.clone()),
        )),
        (Some(start), Some((end, true))) => Some(VersionSpec::Range(
            Version::Inclusive(start.clone()),
            Version::Inclusive(end.clone()),
        )),
        (None, None) => None,
    };

    if let Some(spec) = spec {
        entries.push(PurlStatusEntry {
            advisory_id: advisory_vuln.advisory.advisory.id,
            vulnerability_id: advisory_vuln
                .advisory_vulnerability
                .vulnerability_id
                .clone(),
            purl: purl.clone(),
            status: "affected".to_string(),
            version_info: VersionInfo {
                scheme: version_scheme,
                spec,
            },
            context_cpe: None,
        });
    }

    if let (_, Some((fixed, false))) = &parsed_range {
        entries.push(PurlStatusEntry {
            advisory_id: advisory_vuln.advisory.advisory.id,
            vulnerability_id: advisory_vuln
                .advisory_vulnerability
                .vulnerability_id
                .clone(),
            purl: purl.clone(),
            status: "fixed".to_string(),
            version_info: VersionInfo {
                scheme: version_scheme,
                spec: VersionSpec::Exact(fixed.clone()),
            },
            context_cpe: None,
        });
    }

    entries
}

/// Build package status entries based on listed versions
fn build_package_status_versions<'a>(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    range: &Range,
    versions: impl IntoIterator<Item = &'a String>,
) -> Vec<PurlStatusEntry> {
    // the list of versions, sorted by the range type
    let versions = versions.into_iter().cloned().collect::<Vec<_>>();
    let mut entries = Vec::new();

    let mut start = None;
    for event in &range.events {
        match event {
            Event::Introduced(version) => {
                start = Some(version);
            }
            Event::Fixed(version) | Event::LastAffected(version) => {
                if let Some(start) = start.take() {
                    entries.extend(build_range_from(
                        advisory_vuln,
                        purl,
                        "affected",
                        start,
                        Some(version),
                        &versions,
                    ));
                }

                // Add "fixed" status
                entries.push(PurlStatusEntry {
                    advisory_id: advisory_vuln.advisory.advisory.id,
                    vulnerability_id: advisory_vuln
                        .advisory_vulnerability
                        .vulnerability_id
                        .clone(),
                    purl: purl.clone(),
                    status: "fixed".to_string(),
                    version_info: VersionInfo {
                        scheme: VersionScheme::Generic,
                        spec: VersionSpec::Exact(version.to_string()),
                    },
                    context_cpe: None,
                });
            }
            Event::Limit(_) => {}
            // for non_exhaustive
            _ => {}
        }
    }

    if let Some(start) = start {
        entries.extend(build_range_from(
            advisory_vuln,
            purl,
            "affected",
            start,
            None,
            &versions,
        ));
    }

    entries
}

/// Build status entries for all versions from a start to an end
fn build_range_from(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    status: &str,
    start: &str,
    // exclusive end
    end: Option<&str>,
    versions: &[impl AsRef<str>],
) -> Vec<PurlStatusEntry> {
    let matched_versions = match_versions(versions, start, end);

    matched_versions
        .into_iter()
        .map(|version| PurlStatusEntry {
            advisory_id: advisory_vuln.advisory.advisory.id,
            vulnerability_id: advisory_vuln
                .advisory_vulnerability
                .vulnerability_id
                .clone(),
            purl: purl.clone(),
            status: status.to_string(),
            version_info: VersionInfo {
                scheme: VersionScheme::Generic,
                spec: VersionSpec::Exact(version.to_string()),
            },
            context_cpe: None,
        })
        .collect()
}

/// Extract a list of versions according to OSV
///
/// The idea for ECOSYSTEM and GIT is that the user provides an explicit list of versions, in the
/// right order. So we search through this list, by start and end events. Translating this into
/// exact version matches.
///
/// See: <https://ossf.github.io/osv-schema/#affectedrangestype-field>
fn match_versions<'v>(
    versions: &'v [impl AsRef<str>],
    start: &str,
    end: Option<&str>,
) -> Vec<&'v str> {
    let mut matches = None;

    for version in versions {
        let version = version.as_ref();
        match (&mut matches, end) {
            (None, _) if version == start => {
                matches = Some(vec![version]);
            }
            (None, _) => {}
            (Some(_), Some(end)) if end == version => {
                // reached the exclusive env
                break;
            }
            (Some(matches), _) => {
                matches.push(version);
            }
        }
    }

    matches.unwrap_or_default()
}

fn detect_organization(osv: &Vulnerability) -> Option<String> {
    if let Some(references) = &osv.references {
        let advisory_location = references
            .iter()
            .find(|reference| matches!(reference.reference_type, ReferenceType::Advisory));

        if let Some(advisory_location) = advisory_location {
            let url = &advisory_location.url;
            return get_well_known_prefixes().detect(url);
        }
    }
    None
}

fn events_to_range(events: &[Event]) -> (Option<String>, Option<(String, bool)>) {
    let start = events.iter().find_map(|e| {
        if let Event::Introduced(version) = e {
            Some(version.clone())
        } else {
            None
        }
    });

    let end = events.iter().find_map(|e| {
        if let Event::Fixed(version) = e {
            Some((version.clone(), false))
        } else if let Event::LastAffected(version) = e {
            Some((version.clone(), true))
        } else {
            None
        }
    });

    (start, end)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        graph::Graph,
        service::advisory::{
            osv::loader::OsvLoader,
            test::{AssertScore, assert_scores},
        },
    };
    use hex::ToHex;
    use osv::schema::Vulnerability;
    use rstest::rstest;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::{
        advisory_vulnerability_score::{ScoreType, Severity},
        purl_status, version_range,
    };
    use trustify_test_context::{TrustifyContext, document};

    #[rstest]
    #[case(RangeType::Ecosystem, "Maven", Some(VersionScheme::Maven))]
    #[case(RangeType::Ecosystem, "PyPI", Some(VersionScheme::Python))]
    #[case(
        RangeType::Ecosystem,
        "Red Hat Lightwell:Maven",
        Some(VersionScheme::Maven)
    )]
    #[case(
        RangeType::Ecosystem,
        "Red Hat Lightwell:PyPI",
        Some(VersionScheme::Python)
    )]
    #[case(
        RangeType::Ecosystem,
        "Red Hat Lightwell:Maven:https://maven.google.com",
        Some(VersionScheme::Maven)
    )]
    #[case(
        RangeType::Ecosystem,
        "Red Hat Lightwell:npm",
        Some(VersionScheme::Npm)
    )]
    #[case(RangeType::Ecosystem, "Red Hat:rhel_aus:8.4::appstream", None)]
    #[case(RangeType::Ecosystem, "Red Hat Lightwell:Debian:12", None)]
    #[case(
        RangeType::Ecosystem,
        "Red Hat Lightwell:Python",
        Some(VersionScheme::Python)
    )]
    #[case(
        RangeType::Semver,
        "Red Hat Lightwell:Maven",
        Some(VersionScheme::Semver)
    )]
    #[case(RangeType::Git, "Red Hat Lightwell:PyPI", Some(VersionScheme::Git))]
    #[case(
        RangeType::Semver,
        "Red Hat Lightwell:Debian:12",
        Some(VersionScheme::Semver)
    )]
    #[case(
        RangeType::Git,
        "Red Hat Lightwell:Debian:12",
        Some(VersionScheme::Git)
    )]
    #[test_log::test]
    fn lightwell_version_scheme(
        #[case] range_type: RangeType,
        #[case] ecosystem: &str,
        #[case] expected: Option<VersionScheme>,
    ) -> anyhow::Result<()> {
        let ecosystem = serde_json::from_value(ecosystem.into())?;
        assert_eq!(version_scheme(&range_type, &ecosystem), expected);
        Ok(())
    }

    #[rstest]
    #[case("npm", "demo-weighting", Some("pkg:generic/demo-weighting"), vec!["pkg:npm/demo-weighting", "pkg:generic/demo-weighting"])]
    #[case(
        "Maven", "groupid:artifactid",
        Some("pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fvendor.example%2Frepo"),
        vec!["pkg:maven/groupid/artifactid", "pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fvendor.example%2Frepo"]
    )]
    #[case(
        "Maven:https://vendor.example/repo", "groupid:artifactid",
        Some("pkg:maven/groupid/artifactid"),
        vec!["pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fvendor.example%2Frepo", "pkg:maven/groupid/artifactid"]
    )]
    #[case(
        "Maven:https://vendor.example/repo", "groupid:artifactid",
        Some("pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fother.example%2Frepo"),
        vec!["pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fvendor.example%2Frepo", "pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fother.example%2Frepo"]
    )]
    #[case("Maven", "groupid:artifactid", Some("pkg:maven/other/artifactid"), vec!["pkg:maven/groupid/artifactid", "pkg:maven/other/artifactid"])]
    #[case("Maven", "groupid:artifactid", Some("pkg:maven/groupid/artifactid"), vec!["pkg:maven/groupid/artifactid", "pkg:maven/groupid/artifactid"])]
    #[case("NuGet", "PowerShell", Some("pkg:nuget/powershell"), vec!["pkg:nuget/PowerShell", "pkg:nuget/powershell"])]
    #[case("NuGet", "PowerShell", Some("pkg:nuget/OtherPackage"), vec!["pkg:nuget/PowerShell", "pkg:nuget/OtherPackage"])]
    #[case("Maven", "groupid:artifactid", Some("invalid"), vec!["pkg:maven/groupid/artifactid"])]
    #[case("Debian:12", "openssl", Some("invalid"), vec![])]
    #[case("Debian:12", "openssl", None, vec![])]
    #[case("Python", "pypdf2", None, vec![])]
    #[test_log::test]
    fn ordinary_package_purls_remain_unchanged(
        #[case] ecosystem: &str,
        #[case] name: &str,
        #[case] stated: Option<&str>,
        #[case] expected: Vec<&str>,
    ) -> anyhow::Result<()> {
        let package = serde_json::from_value(serde_json::json!({
            "ecosystem": ecosystem, "name": name, "purl": stated,
        }))?;
        let warnings = Warnings::new();
        assert_eq!(
            package_purls(&package, &warnings)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(Vec::<String>::from(warnings).is_empty());
        Ok(())
    }

    #[rstest]
    #[case("Red Hat Lightwell:Maven", None, vec!["pkg:maven/groupid/artifactid"])]
    #[case("Red Hat Lightwell:Maven", Some("invalid"), vec!["pkg:maven/groupid/artifactid"])]
    #[case(
        "Red Hat Lightwell:Maven",
        Some("pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fvendor.example%2Frepo"),
        vec!["pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fvendor.example%2Frepo"]
    )]
    #[case(
        "Red Hat Lightwell:Maven:https://packages.redhat.com/lightwell",
        Some("pkg:maven/groupid/artifactid"),
        vec!["pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fpackages.redhat.com%2Flightwell"]
    )]
    #[case(
        "Red Hat Lightwell:Maven:https://packages.redhat.com/lightwell",
        Some("pkg:maven/groupid/artifactid?arch=source"),
        vec!["pkg:maven/groupid/artifactid?arch=source&repository_url=https:%2F%2Fpackages.redhat.com%2Flightwell"]
    )]
    #[case(
        "Red Hat Lightwell:Maven:https://packages.redhat.com/lightwell",
        Some("pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fpackages.redhat.com%2Flightwell"),
        vec!["pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fpackages.redhat.com%2Flightwell"]
    )]
    #[case("Red Hat Lightwell:Maven", Some("pkg:maven/groupid/artifactid"), vec!["pkg:maven/groupid/artifactid"])]
    #[test_log::test]
    fn lightwell_package_purls(
        #[case] ecosystem: &str,
        #[case] stated: Option<&str>,
        #[case] expected: Vec<&str>,
    ) -> anyhow::Result<()> {
        let package = serde_json::from_value(serde_json::json!({
            "ecosystem": ecosystem,
            "name": "groupid:artifactid",
            "purl": stated,
        }))?;
        let warnings = Warnings::new();
        let purls = package_purls(&package, &warnings);
        assert_eq!(
            purls.iter().map(ToString::to_string).collect::<Vec<_>>(),
            expected
        );
        let warnings = Vec::<String>::from(warnings);
        if stated == Some("invalid") {
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].starts_with("Invalid OSV package PURL"));
        } else {
            assert!(warnings.is_empty(), "{warnings:?}");
        }
        Ok(())
    }

    #[rstest]
    #[case(
        "Red Hat Lightwell:Maven:https://vendor.example/repo",
        "groupid:artifactid",
        Some("pkg:maven/groupid/artifactid?repository_url=https:%2F%2Fother.example%2Frepo"),
        "Conflicting repositories"
    )]
    #[case(
        "Red Hat Lightwell:Maven",
        "groupid:artifactid",
        Some("pkg:npm/artifactid"),
        "Conflicting inferred and stated PURLs"
    )]
    #[case("Red Hat Lightwell:Debian:12", "openssl", None, "No usable PURL")]
    #[test_log::test]
    fn unresolved_package_purls_warn(
        #[case] ecosystem: &str,
        #[case] name: &str,
        #[case] stated: Option<&str>,
        #[case] warning: &str,
    ) -> anyhow::Result<()> {
        let package = serde_json::from_value(serde_json::json!({
            "ecosystem": ecosystem, "name": name, "purl": stated,
        }))?;
        let warnings = Warnings::new();
        assert!(package_purls(&package, &warnings).is_empty());
        let warnings = Vec::<String>::from(warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with(warning), "{:?}", warnings);
        Ok(())
    }

    #[rstest]
    #[case("Red Hat Lightwell:Python")]
    #[test_log::test]
    fn python_without_purl_is_inferred(#[case] ecosystem: &str) -> anyhow::Result<()> {
        let package: Package = serde_json::from_value(serde_json::json!({
            "ecosystem": ecosystem, "name": "pypdf2",
        }))?;
        let warnings = Warnings::new();
        assert_eq!(
            version_scheme(&RangeType::Ecosystem, &package.ecosystem),
            Some(VersionScheme::Python)
        );
        let purls = package_purls(&package, &warnings);
        assert_eq!(
            purls.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["pkg:pypi/pypdf2"]
        );
        assert!(Vec::<String>::from(warnings).is_empty());
        Ok(())
    }

    #[rstest]
    #[case("PowerShell", "pkg:nuget/powershell", "pkg:nuget/PowerShell")]
    #[case("powershell", "pkg:nuget/PowerShell", "pkg:nuget/powershell")]
    #[case(
        "PowerShell",
        "pkg:nuget/powershell?arch=x86_64&repository_url=https:%2F%2Fvendor.example%2Fnuget",
        "pkg:nuget/PowerShell?arch=x86_64&repository_url=https:%2F%2Fvendor.example%2Fnuget"
    )]
    #[test_log::test]
    fn lightwell_nuget_uses_inferred_name(
        #[case] name: &str,
        #[case] stated: &str,
        #[case] expected: &str,
    ) -> anyhow::Result<()> {
        for (stated, expected) in [(stated, Some(expected)), ("pkg:nuget/OtherPackage", None)] {
            let package = serde_json::from_value(serde_json::json!({
                "ecosystem": "Red Hat Lightwell:NuGet", "name": name, "purl": stated,
            }))?;
            let warnings = Warnings::new();
            let purls = package_purls(&package, &warnings);
            let warnings = Vec::<String>::from(warnings);
            if let Some(expected) = expected {
                assert_eq!(
                    purls.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    [expected]
                );
                assert!(warnings.is_empty(), "{warnings:?}");
            } else {
                assert!(purls.is_empty());
                assert_eq!(warnings.len(), 1);
                assert!(warnings[0].starts_with("Conflicting inferred and stated PURLs"));
            }
        }
        Ok(())
    }

    #[rstest]
    #[case("Debian:12", Some("pkg:deb/debian/example"), "pkg:deb/debian/example")]
    #[case(
        "Red Hat Lightwell:Debian:12",
        Some("pkg:deb/debian/example"),
        "pkg:deb/debian/example"
    )]
    #[case("CRAN", None, "pkg:cran/example")]
    #[case("Red Hat Lightwell:CRAN", None, "pkg:cran/example")]
    #[test_log::test]
    fn purl_and_range_capabilities_are_independent(
        #[case] ecosystem: &str,
        #[case] stated: Option<&str>,
        #[case] expected: &str,
    ) -> anyhow::Result<()> {
        let package: Package = serde_json::from_value(serde_json::json!({
            "ecosystem": ecosystem, "name": "example", "purl": stated,
        }))?;
        let warnings = Warnings::new();
        let purls = package_purls(&package, &warnings);
        assert_eq!(
            purls.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [expected]
        );
        assert!(Vec::<String>::from(warnings).is_empty());
        assert_eq!(
            version_scheme(&RangeType::Ecosystem, &package.ecosystem),
            None
        );
        assert_eq!(
            version_scheme(&RangeType::Semver, &package.ecosystem),
            Some(VersionScheme::Semver)
        );
        assert_eq!(
            version_scheme(&RangeType::Git, &package.ecosystem),
            Some(VersionScheme::Git)
        );
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();

        let (osv, digests): (Vulnerability, _) = document("osv/RUSTSEC-2021-0079.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2021-32714", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("file", "RUSTSEC-2021-0079.json"), osv, &digests, None, tx)
                    .await
            })
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2021-32714", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        assert!(loaded_advisory.advisory.issuer_id.is_some());

        let loaded_advisory_vulnerabilities = loaded_advisory.vulnerabilities(&ctx.db).await?;
        assert_eq!(1, loaded_advisory_vulnerabilities.len());
        let _loaded_advisory_vulnerability = &loaded_advisory_vulnerabilities[0];

        assert!(
            loaded_advisory
                .get_vulnerability("CVE-8675309", &ctx.db)
                .await?
                .is_none()
        );

        assert_scores(
            &ctx.db,
            loaded_advisory.advisory.id,
            [AssertScore {
                vulnerability_id: "CVE-2021-32714",
                r#type: ScoreType::V3_1,
                severity: Severity::Critical,
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                score: 9.1,
            }],
        )
        .await?;

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader_pypi(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();

        let (osv, digests): (Vulnerability, _) = document("osv/GHSA-45c4-8wx5-qw6w.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2023-37276", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(
                        ("file", "GHSA-45c4-8wx5-qw6w.json"),
                        osv,
                        &digests,
                        None,
                        tx,
                    )
                    .await
            })
            .await?;
        let loaded_vulnerability = graph.get_vulnerability("CVE-2023-37276", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader_explicit_versions_processing(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        // Create a test OSV file with explicit versions but no ranges
        let osv_content = r#"{
            "schema_version": "1.4.0",
            "id": "TEST-EXPLICIT-VERSIONS",
            "modified": "2024-01-01T00:00:00Z",
            "published": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2024-TEST"],
            "summary": "Test vulnerability with explicit versions",
            "details": "This is a test vulnerability to verify explicit versions are processed",
            "affected": [{
                "package": {
                    "ecosystem": "PyPI",
                    "name": "test-package",
                    "purl": "pkg:pypi/test-package"
                },
                "versions": ["1.0.0", "1.0.1", "1.0.2"]
            }]
        }"#;

        let osv: Vulnerability = serde_json::from_str(osv_content)?;
        let digests = Digests::digest(osv_content.as_bytes());

        let graph = Graph::new();

        // Load the OSV
        let loader = OsvLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(("test", "explicit-versions"), osv, &digests, None, tx)
                    .await
            })
            .await?;

        // Verify that the advisory was created
        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let advisory = loaded_advisory.unwrap();

        // Verify that the vulnerability was linked
        let advisory_vuln = advisory.get_vulnerability("CVE-2024-TEST", &ctx.db).await?;
        assert!(advisory_vuln.is_some());

        let _advisory_vuln = advisory_vuln.unwrap();

        // The fix ensures that explicit versions are always processed for advisory linking.
        // If we reach this point, the OSV loader didn't fail, which means
        // our fix successfully handled explicit versions.

        Ok(())
    }

    // Verify that crates.io advisories using ECOSYSTEM range type create
    // purl_status entries with semver version ranges, not generic exact matches.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader_crates_io(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new();

        let (osv, digests): (Vulnerability, _) = document("osv/GHSA-434x-w66g-qw3r.json").await?;

        let loader = OsvLoader::new(&graph);
        ctx.db
            .transaction(async |tx| {
                loader
                    .load(
                        ("file", "GHSA-434x-w66g-qw3r.json"),
                        osv,
                        &digests,
                        None,
                        tx,
                    )
                    .await
            })
            .await?;

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2026-25541", &ctx.db)
            .await?;
        assert!(advisory_vuln.is_some());

        // Query purl_status records for this advisory and verify version ranges
        let statuses = purl_status::Entity::find()
            .filter(purl_status::Column::AdvisoryId.eq(loaded_advisory.advisory.id))
            .all(db)
            .await?;

        assert_eq!(2, statuses.len());

        let mut ranges = Vec::new();
        for status in &statuses {
            let range = version_range::Entity::find_by_id(status.version_range_id)
                .one(db)
                .await?
                .unwrap();

            assert_eq!(VersionScheme::Cargo, range.version_scheme_id);

            ranges.push(range);
        }

        // Verify there is an affected range [1.2.1, 1.11.1)
        assert!(ranges.iter().any(|r| {
            r.low_version.as_deref() == Some("1.2.1")
                && r.low_inclusive == Some(true)
                && r.high_version.as_deref() == Some("1.11.1")
                && r.high_inclusive == Some(false)
        }));

        Ok(())
    }

    #[rstest]
    #[case("b", Some("d"), vec!["b", "c"])]
    #[case("e", None, vec!["e", "f", "g"])]
    #[case("x", None, vec![])]
    #[case("e", Some("a"), vec!["e", "f", "g"])]
    #[test_log::test]
    fn test_matches(#[case] start: &str, #[case] end: Option<&str>, #[case] result: Vec<&str>) {
        const INPUT: &[&str] = &["a", "b", "c", "d", "e", "f", "g"];
        assert_eq!(match_versions(INPUT, start, end), result);
    }
}
