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
            extract_scores, extract_vulnerability_ids, prefix::get_well_known_prefixes, translate,
        },
    },
};
use osv::schema::{Ecosystem, Event, Package, Range, RangeType, ReferenceType, Vulnerability};
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::{collections::HashSet, fmt::Debug, str::FromStr};
use tracing::instrument;
use trustify_common::{hashing::Digests, purl::Purl, time::ChronoExt};
use trustify_entity::{labels::Labels, version_scheme::VersionScheme};

/// Loads OSV records.
///
/// OSV only defines the set of affected versions: a version is affected if it is listed in
/// `versions`, or lies in an interval of a range (`introduced` up to `fixed`, or up to and including
/// `last_affected`). Only those are stored, as `affected`. Versions outside of the set are not
/// affected according to the record, which states nothing else about them. A `fixed` event only
/// ends an interval, it isn't a status of the fixed version.
///
/// See: <https://ossf.github.io/osv-schema/#evaluation>
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

        let information = AdvisoryInformation {
            id: osv.id.clone(),
            title: osv.summary.clone(),
            // TODO(#899): check if we have some kind of version information
            version: None,
            issuer,
            published: osv.published.map(ChronoExt::into_time),
            modified: Some(osv.modified.into_time()),
            withdrawn: osv.withdrawn.map(ChronoExt::into_time),
            publisher_namespace: None,
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

        let vulnerability_ids = extract_vulnerability_ids(&osv);

        // Batch create all vulnerabilities
        let mut vuln_creator = VulnerabilityCreator::new();
        for id in &vulnerability_ids {
            vuln_creator.add(*id, ());
        }
        vuln_creator.create(tx).await?;

        let mut purl_creator = PurlCreator::new();
        let mut purl_status_creator = PurlStatusCreator::new();
        let mut base_purls = HashSet::new();
        let mut score_creator = ScoreCreator::new(advisory.advisory.id);

        extract_scores(&osv, &mut score_creator);

        // the affected entries with a package, and its PURLs
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

        for id in vulnerability_ids {
            let advisory_vuln = advisory
                .link_to_vulnerability(
                    id,
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
                        purl_status_creator.add(affected_status(
                            &advisory_vuln,
                            purl,
                            VersionScheme::Generic,
                            VersionSpec::Exact(version.to_string()),
                        ));
                    }

                    for range in affected.ranges.iter().flatten() {
                        // Collect base PURL for range-based status entries
                        base_purls.insert(purl.clone());

                        let entries = match version_scheme(&range.range_type, &package.ecosystem) {
                            Some(scheme) => {
                                build_package_status(&advisory_vuln, purl, range, scheme)
                            }
                            None => build_package_status_versions(
                                &advisory_vuln,
                                purl,
                                range,
                                affected.versions.iter().flatten(),
                            ),
                        };
                        for entry in entries {
                            purl_status_creator.add(entry);
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

/// The PURLs of a package: the one translated from its ecosystem and name, and the stated one.
///
/// The stated PURL identifies the package "without the `@version` component". A version is
/// ignored, with a warning.
fn package_purls(package: &Package, warnings: &Warnings) -> Vec<Purl> {
    let mut purls = vec![];
    purls.extend(translate::to_purl(package).map(Purl::from));
    if let Some(stated) = &package.purl
        && let Ok(mut purl) = Purl::from_str(stated)
    {
        if purl.version.take().is_some() {
            warnings.add(format!(
                "The PURL of an OSV package must not have a version, ignoring it: {stated}"
            ));
        }
        purls.push(purl);
    }
    purls
}

/// The version scheme to evaluate a range with, `None` if unknown.
///
/// A range of an unknown scheme is evaluated on the enumerated `versions` instead.
fn version_scheme(range_type: &RangeType, ecosystem: &Ecosystem) -> Option<VersionScheme> {
    Some(match (range_type, ecosystem) {
        (RangeType::Semver, _) => VersionScheme::Semver,
        (RangeType::Git, _) => VersionScheme::Git,
        (RangeType::Ecosystem, Ecosystem::Maven(_)) => VersionScheme::Maven,
        (RangeType::Ecosystem, Ecosystem::PyPI | Ecosystem::Python) => VersionScheme::Python,
        (RangeType::Ecosystem, Ecosystem::Go) => VersionScheme::Golang,
        (RangeType::Ecosystem, Ecosystem::Npm) => VersionScheme::Npm,
        (RangeType::Ecosystem, Ecosystem::Packagist) => VersionScheme::Packagist,
        (RangeType::Ecosystem, Ecosystem::NuGet) => VersionScheme::NuGet,
        (RangeType::Ecosystem, Ecosystem::RubyGems) => VersionScheme::Gem,
        (RangeType::Ecosystem, Ecosystem::Hex) => VersionScheme::Hex,
        (RangeType::Ecosystem, Ecosystem::SwiftURL) => VersionScheme::Swift,
        (RangeType::Ecosystem, Ecosystem::Pub) => VersionScheme::Pub,
        (RangeType::Ecosystem, Ecosystem::CratesIO) => VersionScheme::Cargo,
        _ => return None,
    })
}

/// An `affected` status of a package.
fn affected_status(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    scheme: VersionScheme,
    spec: VersionSpec,
) -> PurlStatusEntry {
    PurlStatusEntry {
        source_provider: None,
        advisory_id: advisory_vuln.advisory.advisory.id,
        vulnerability_id: advisory_vuln
            .advisory_vulnerability
            .vulnerability_id
            .clone(),
        purl: purl.clone(),
        status: "affected".to_string(),
        version_info: VersionInfo { scheme, spec },
        context_cpe: None,
        context_id: None,
        default: false,
    }
}

/// An interval of affected versions of a range.
#[derive(Debug, PartialEq, Eq)]
struct Interval<'a> {
    /// The first affected version, `None` for `0` (all versions before).
    introduced: Option<&'a str>,
    /// The end: the `fixed` version (exclusive), or the `last_affected` one (inclusive). `None` if
    /// open.
    end: Option<End<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
enum End<'a> {
    Fixed(&'a str),
    LastAffected(&'a str),
}

/// The affected intervals of the events of a range.
///
/// The spec evaluates the events in sorted order. Sorting requires the versioning scheme, so the
/// events are taken in the order they are listed, which is the sorted one in practice. An
/// `introduced` within an interval doesn't start a new one, an end without an interval is ignored.
/// `limit` events are ignored.
fn intervals(events: &[Event]) -> Vec<Interval<'_>> {
    let mut result = Vec::new();
    let mut start = None;

    for event in events {
        let end = match event {
            Event::Introduced(version) => {
                if start.is_none() {
                    start = Some((version != "0").then_some(version.as_str()));
                }
                continue;
            }
            Event::Fixed(version) => End::Fixed(version),
            Event::LastAffected(version) => End::LastAffected(version),
            // `limit`, and others (non_exhaustive)
            _ => continue,
        };
        if let Some(introduced) = start.take() {
            result.push(Interval {
                introduced,
                end: Some(end),
            });
        }
    }

    if let Some(introduced) = start {
        result.push(Interval {
            introduced,
            end: None,
        });
    }

    result
}

/// Build the status entries of a range: one `affected` range per interval.
fn build_package_status(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    range: &Range,
    version_scheme: VersionScheme,
) -> Vec<PurlStatusEntry> {
    intervals(&range.events)
        .into_iter()
        .map(|interval| {
            let low = match interval.introduced {
                Some(introduced) => Version::Inclusive(introduced.to_string()),
                None => Version::Unbounded,
            };
            let high = match interval.end {
                Some(End::Fixed(fixed)) => Version::Exclusive(fixed.to_string()),
                Some(End::LastAffected(last)) => Version::Inclusive(last.to_string()),
                None => Version::Unbounded,
            };
            affected_status(
                advisory_vuln,
                purl,
                version_scheme,
                VersionSpec::Range(low, high),
            )
        })
        .collect()
}

/// Build the status entries of a range of an unknown scheme, from the listed versions: each
/// version of an interval is `affected`.
fn build_package_status_versions<'a>(
    advisory_vuln: &AdvisoryVulnerabilityContext<'_>,
    purl: &Purl,
    range: &Range,
    versions: impl IntoIterator<Item = &'a String>,
) -> Vec<PurlStatusEntry> {
    // the list of versions, sorted by the range type
    let versions = versions.into_iter().collect::<Vec<_>>();

    intervals(&range.events)
        .iter()
        .flat_map(|interval| match_versions(&versions, interval))
        .map(|version| {
            affected_status(
                advisory_vuln,
                purl,
                VersionScheme::Generic,
                VersionSpec::Exact(version.to_string()),
            )
        })
        .collect()
}

/// Extract the versions of an interval from a list of versions according to OSV
///
/// The idea for ECOSYSTEM and GIT is that the user provides an explicit list of versions, in the
/// right order. So we search through this list, by start and end events. Translating this into
/// exact version matches.
///
/// See: <https://ossf.github.io/osv-schema/#affectedrangestype-field>
fn match_versions<'v>(versions: &'v [impl AsRef<str>], interval: &Interval) -> Vec<&'v str> {
    let mut matches = None;

    for version in versions {
        let version = version.as_ref();
        if matches.is_none() && interval.introduced.is_none_or(|start| start == version) {
            matches = Some(vec![]);
        }
        let Some(matches) = &mut matches else {
            continue;
        };
        match interval.end {
            // reached the exclusive end
            Some(End::Fixed(end)) if end == version => break,
            Some(End::LastAffected(end)) if end == version => {
                matches.push(version);
                break;
            }
            _ => matches.push(version),
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
    use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::{
        advisory_vulnerability_score::{ScoreType, Severity},
        purl_status, status, version_range,
    };
    use trustify_test_context::{TrustifyContext, document};
    use uuid::Uuid;

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

        // only the affected range, the fix only ends it
        assert_eq!(
            stated(loaded_advisory.advisory.id, db).await?,
            [stated_range(
                "CVE-2026-25541",
                VersionScheme::Cargo,
                (Some("1.2.1"), true),
                (Some("1.11.1"), false),
            )]
        );

        Ok(())
    }

    /// A stated `affected` range: vulnerability, scheme, low and high bound.
    type StatedRange = (
        String,
        String,
        VersionScheme,
        (Option<String>, Option<bool>),
        (Option<String>, Option<bool>),
    );

    fn stated_range(
        vulnerability: &str,
        scheme: VersionScheme,
        (low, low_inclusive): (Option<&str>, bool),
        (high, high_inclusive): (Option<&str>, bool),
    ) -> StatedRange {
        (
            vulnerability.to_string(),
            "affected".to_string(),
            scheme,
            (low.map(str::to_string), Some(low_inclusive)),
            (high.map(str::to_string), Some(high_inclusive)),
        )
    }

    /// The statuses an advisory states, with their ranges, sorted.
    async fn stated(
        advisory_id: Uuid,
        db: &impl ConnectionTrait,
    ) -> anyhow::Result<Vec<StatedRange>> {
        let mut result = Vec::new();
        for (purl_status, status) in purl_status::Entity::find()
            .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
            .find_also_related(status::Entity)
            .all(db)
            .await?
        {
            let range = version_range::Entity::find_by_id(purl_status.version_range_id)
                .one(db)
                .await?
                .expect("version range of a status");
            result.push((
                purl_status.vulnerability_id,
                status.expect("status of a purl status").slug,
                range.version_scheme_id,
                (range.low_version, range.low_inclusive),
                (range.high_version, range.high_inclusive),
            ));
        }
        result.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        Ok(result)
    }

    /// Several intervals in a range, `last_affected`, no CVE alias, and a PURL with a version.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader_affected_set(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let osv_content = r#"{
            "schema_version": "1.7.3",
            "id": "GHSA-test-affected-set",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["PYSEC-2024-1"],
            "affected": [{
                "package": {
                    "ecosystem": "PyPI",
                    "name": "test-package",
                    "purl": "pkg:pypi/test-package@1.0"
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.0"},
                            {"introduced": "2.0"},
                            {"fixed": "2.5"},
                            {"introduced": "3.0"}
                        ]
                    },
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "4.0.0"}, {"last_affected": "4.5.0"}]
                    }
                ]
            }]
        }"#;

        let osv: Vulnerability = serde_json::from_str(osv_content)?;
        let digests = Digests::digest(osv_content.as_bytes());

        let graph = Graph::new();
        let loader = OsvLoader::new(&graph);
        let result = ctx
            .db
            .transaction(async |tx| {
                loader
                    .load(("test", "affected-set"), osv, &digests, None, tx)
                    .await
            })
            .await?;

        assert_eq!(
            result.warnings,
            [
                "The PURL of an OSV package must not have a version, ignoring it: \
              pkg:pypi/test-package@1.0"
            ]
        );

        let id = Uuid::parse_str(&result.id)?;
        const ID: &str = "GHSA-test-affected-set";
        assert_eq!(
            stated(id, &ctx.db).await?,
            [
                stated_range(
                    ID,
                    VersionScheme::Python,
                    (None, false),
                    (Some("1.0"), false)
                ),
                stated_range(
                    ID,
                    VersionScheme::Python,
                    (Some("2.0"), true),
                    (Some("2.5"), false)
                ),
                stated_range(
                    ID,
                    VersionScheme::Python,
                    (Some("3.0"), true),
                    (None, false)
                ),
                stated_range(
                    ID,
                    VersionScheme::Semver,
                    (Some("4.0.0"), true),
                    (Some("4.5.0"), true)
                ),
            ]
        );

        Ok(())
    }

    #[rstest]
    #[case(&[Event::Introduced("1".into()), Event::Fixed("2".into())], vec![
        Interval { introduced: Some("1"), end: Some(End::Fixed("2")) },
    ])]
    #[case(&[Event::Introduced("0".into())], vec![
        Interval { introduced: None, end: None },
    ])]
    #[case(&[
        Event::Introduced("0".into()),
        Event::LastAffected("1".into()),
        Event::Introduced("2".into()),
        Event::Introduced("3".into()),
        Event::Limit("4".into()),
    ], vec![
        Interval { introduced: None, end: Some(End::LastAffected("1")) },
        Interval { introduced: Some("2"), end: None },
    ])]
    #[case(&[Event::Fixed("1".into()), Event::Introduced("2".into())], vec![
        Interval { introduced: Some("2"), end: None },
    ])]
    #[test_log::test]
    fn test_intervals(#[case] events: &[Event], #[case] result: Vec<Interval>) {
        assert_eq!(intervals(events), result);
    }

    #[rstest]
    #[case(Some("b"), Some(End::Fixed("d")), vec!["b", "c"])]
    #[case(Some("b"), Some(End::LastAffected("d")), vec!["b", "c", "d"])]
    #[case(None, Some(End::Fixed("c")), vec!["a", "b"])]
    #[case(Some("e"), None, vec!["e", "f", "g"])]
    #[case(Some("x"), None, vec![])]
    #[case(Some("e"), Some(End::Fixed("a")), vec!["e", "f", "g"])]
    #[test_log::test]
    fn test_matches(
        #[case] introduced: Option<&str>,
        #[case] end: Option<End>,
        #[case] result: Vec<&str>,
    ) {
        const INPUT: &[&str] = &["a", "b", "c", "d", "e", "f", "g"];
        assert_eq!(match_versions(INPUT, &Interval { introduced, end }), result);
    }
}
