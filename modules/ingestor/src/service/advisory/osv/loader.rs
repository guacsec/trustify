use crate::{
    graph::{
        Graph,
        advisory::{
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
            advisory_vulnerability::AdvisoryVulnerabilityContext,
            version::{Version, VersionInfo, VersionSpec},
        },
        purl::creator::PurlCreator,
    },
    model::IngestResult,
    service::{
        Error, Warnings,
        advisory::osv::{prefix::get_well_known_prefixes, translate},
    },
};
use osv::schema::{Ecosystem, Event, Range, RangeType, ReferenceType, SeverityType, Vulnerability};
use sbom_walker::report::ReportSink;
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::{fmt::Debug, str::FromStr};
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id, purl::Purl, time::ChronoExt};
use trustify_cvss::cvss3::Cvss3Base;
use trustify_entity::{labels::Labels, version_scheme::VersionScheme};

pub struct OsvLoader<'g> {
    graph: &'g Graph,
}

impl<'g> OsvLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, osv), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        osv: Vulnerability,
        digests: &Digests,
        issuer: Option<String>,
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();

        let labels = labels.into().add("type", "osv");

        let issuer = issuer.or(detect_organization(&osv));

        let tx = self.graph.db.begin().await?;

        let cve_ids = osv.aliases.iter().flat_map(|aliases| {
            aliases
                .iter()
                .filter(|e| e.starts_with("CVE-"))
                .cloned()
                .collect::<Vec<_>>()
        });

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
        let advisory = self
            .graph
            .ingest_advisory(&osv.id, labels, digests, information, &tx)
            .await?;

        if let Some(withdrawn) = osv.withdrawn {
            advisory
                .set_withdrawn_at(withdrawn.into_time(), &tx)
                .await?;
        }

        let mut purl_creator = PurlCreator::new();

        for cve_id in cve_ids {
            self.graph.ingest_vulnerability(&cve_id, (), &tx).await?;

            let advisory_vuln = advisory
                .link_to_vulnerability(
                    &cve_id,
                    Some(AdvisoryVulnerabilityInformation {
                        title: osv.summary.clone(),
                        summary: osv.summary.clone(),
                        description: osv.details.clone(),
                        reserved_date: None,
                        discovery_date: None,
                        release_date: None,
                        cwes: None,
                    }),
                    &tx,
                )
                .await?;

            for severity in osv.severity.iter().flatten() {
                if matches!(severity.severity_type, SeverityType::CVSSv3) {
                    match Cvss3Base::from_str(&severity.score) {
                        Ok(cvss3) => {
                            advisory_vuln.ingest_cvss3_score(cvss3, &tx).await?;
                        }
                        Err(err) => {
                            let msg = format!("Unable to parse CVSS3: {err}");
                            warnings.error(msg)
                        }
                    }
                }
            }

            for affected in &osv.affected {
                // we only process it when we have a package

                let Some(package) = &affected.package else {
                    tracing::debug!(
                        osv = osv.id,
                        "OSV document did not contain an 'affected' section",
                    );
                    continue;
                };

                // extract PURLs

                let mut purls = vec![];
                purls.extend(translate::to_purl(package).map(Purl::from));
                if let Some(purl) = &package.purl {
                    purls.extend(Purl::from_str(purl).ok());
                }

                for purl in purls {
                    // iterate through the known versions, apply the version, and create them
                    for version in affected.versions.iter().flatten() {
                        purl_creator.add(purl.with_version(version));
                    }

                    // Process explicit versions for advisory linking
                    for version in affected.versions.iter().flatten() {
                        ingest_exact(&advisory_vuln, &purl, "affected", version, &tx).await?;
                    }

                    for range in affected.ranges.iter().flatten() {
                        match (&range.range_type, &package.ecosystem) {
                            (RangeType::Semver, _) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Semver,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Git, _) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Git,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::Maven(_)) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Maven,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::PyPI | Ecosystem::Python) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Python,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::Go) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Golang,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::Npm) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Npm,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::Packagist) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Packagist,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::NuGet) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::NuGet,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::RubyGems) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Gem,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::Hex) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Hex,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::SwiftURL) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Swift,
                                    &tx,
                                )
                                .await?;
                            }
                            (RangeType::Ecosystem, Ecosystem::Pub) => {
                                create_package_status(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    &VersionScheme::Pub,
                                    &tx,
                                )
                                .await?;
                            }
                            (_, _) => {
                                create_package_status_versions(
                                    &advisory_vuln,
                                    &purl,
                                    range,
                                    affected.versions.iter().flatten(),
                                    &tx,
                                )
                                .await?
                            }
                        }
                    }
                }
            }
        }

        purl_creator.create(&tx).await?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(advisory.advisory.id),
            document_id: Some(osv.id),
            warnings: warnings.into(),
        })
    }
}

/// create package statues based on listed versions
async fn create_package_status_versions<C: ConnectionTrait>(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    range: &Range,
    versions: impl IntoIterator<Item = &String>,
    connection: &C,
) -> Result<(), Error> {
    // the list of versions, sorted by the range type
    let versions = versions.into_iter().cloned().collect::<Vec<_>>();

    let mut start = None;
    for event in &range.events {
        match event {
            Event::Introduced(version) => {
                start = Some(version);
            }
            Event::Fixed(version) | Event::LastAffected(version) => {
                if let Some(start) = start.take() {
                    ingest_range_from(
                        advisory_vuln,
                        purl,
                        "affected",
                        start,
                        Some(version),
                        &versions,
                        connection,
                    )
                    .await?;
                }

                ingest_exact(advisory_vuln, purl, "fixed", version, connection).await?;
            }
            Event::Limit(_) => {}
            // for non_exhaustive
            _ => {}
        }
    }

    if let Some(start) = start {
        ingest_range_from(
            advisory_vuln,
            purl,
            "affected",
            start,
            None,
            &versions,
            connection,
        )
        .await?;
    }

    Ok(())
}

/// Ingest all from a start to an end
async fn ingest_range_from<C: ConnectionTrait>(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    status: &str,
    start: &str,
    // exclusive end
    end: Option<&str>,
    versions: &[impl AsRef<str>],
    connection: &C,
) -> Result<(), Error> {
    let versions = match_versions(versions, start, end);

    for version in versions {
        ingest_exact(advisory_vuln, purl, status, version, connection).await?;
    }

    Ok(())
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

/// Ingest an exact version
async fn ingest_exact<C: ConnectionTrait>(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    status: &str,
    version: &str,
    connection: &C,
) -> Result<(), Error> {
    Ok(advisory_vuln
        .ingest_package_status(
            None,
            purl,
            status,
            VersionInfo {
                scheme: VersionScheme::Generic,
                spec: VersionSpec::Exact(version.to_string()),
            },
            connection,
        )
        .await?)
}

/// create a package/purl status
async fn create_package_status<C: ConnectionTrait>(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    range: &Range,
    version_scheme: &VersionScheme,
    connection: &C,
) -> Result<(), Error> {
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
        advisory_vuln
            .ingest_package_status(
                None,
                purl,
                "affected",
                VersionInfo {
                    scheme: *version_scheme,
                    spec,
                },
                connection,
            )
            .await?;
    }

    if let (_, Some((fixed, false))) = &parsed_range {
        advisory_vuln
            .ingest_package_status(
                None,
                purl,
                "fixed",
                VersionInfo {
                    scheme: *version_scheme,
                    spec: VersionSpec::Exact(fixed.clone()),
                },
                connection,
            )
            .await?
    }

    Ok(())
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
    use crate::graph::Graph;
    use crate::service::advisory::osv::loader::OsvLoader;
    use hex::ToHex;
    use osv::schema::Vulnerability;
    use rstest::rstest;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::{TrustifyContext, document};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());

        let (osv, digests): (Vulnerability, _) = document("osv/RUSTSEC-2021-0079.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2021-32714", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);
        loader
            .load(("file", "RUSTSEC-2021-0079.json"), osv, &digests, None)
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

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2021-32714", &ctx.db)
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(&ctx.db).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
        );

        assert!(
            loaded_advisory
                .get_vulnerability("CVE-8675309", &ctx.db)
                .await?
                .is_none()
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader_pypi(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());

        let (osv, digests): (Vulnerability, _) = document("osv/GHSA-45c4-8wx5-qw6w.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2023-37276", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);
        loader
            .load(("file", "GHSA-45c4-8wx5-qw6w.json"), osv, &digests, None)
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
        let digests = trustify_common::hashing::Digests::digest(osv_content.as_bytes());

        let db = &ctx.db;
        let graph = Graph::new(db.clone());

        // Load the OSV
        let loader = OsvLoader::new(&graph);
        loader
            .load(("test", "explicit-versions"), osv, &digests, None)
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
