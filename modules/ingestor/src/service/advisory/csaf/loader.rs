use crate::{
    graph::{
        Graph, Outcome,
        advisory::{
            AdvisoryContext, AdvisoryInformation, AdvisoryVulnerabilityInformation,
            advisory_vulnerability::AdvisoryVulnerabilityContext,
        },
        cvss::ScoreCreator,
        vulnerability::creator::VulnerabilityCreator,
    },
    model::IngestResult,
    service::{
        Error, Warnings,
        advisory::csaf::{
            RemediationCreator, StatusCreator, extract_scores,
            util::gen_identifier,
            value::{self, OnInvalidData},
        },
    },
};
use csaf::schema::csaf2_0::schema::{
    CommonSecurityAdvisoryFramework as Csaf, ProductStatus, Remediation, Vulnerability,
};
use sbom_walker::report::ReportSink;
use sea_orm::{ConnectionTrait, TransactionTrait};
use semver::Version;
use std::{fmt::Debug, str::FromStr};
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::labels::Labels;

/// Collect the advisory information from a CSAF document.
fn advisory_information(
    csaf: &Csaf,
    on_invalid: OnInvalidData,
    report: &dyn ReportSink,
) -> Result<AdvisoryInformation, Error> {
    let tracking = &csaf.document.tracking;

    Ok(AdvisoryInformation {
        id: tracking.id.to_string(),
        // TODO: consider failing if the version doesn't parse
        version: parse_csaf_version(csaf),
        title: Some(csaf.document.title.to_string()),
        issuer: Some(csaf.document.publisher.name.to_string()),
        published: on_invalid.validate(value::date(&tracking.initial_release_date), report)?,
        modified: on_invalid.validate(value::date(&tracking.current_release_date), report)?,
        withdrawn: None,
        publisher_namespace: Some(csaf.document.publisher.namespace.to_string()),
    })
}

/// Parse a CSAF tracking version.
///
/// This can be either a semantic version or a plain number. In case of a plain number, we use
/// this as a major version.
fn parse_csaf_version(csaf: &Csaf) -> Option<Version> {
    // TODO: consider checking individual tracking records too
    let version = csaf.document.tracking.version.as_str();
    if version.contains('.') {
        version.parse().ok()
    } else {
        u64::from_str(version)
            .map(|major| Version {
                major,
                minor: 0,
                patch: 0,
                pre: Default::default(),
                build: Default::default(),
            })
            .ok()
    }
}

pub struct CsafLoader<'g> {
    graph: &'g Graph,
    /// What to do when the document carries a value we cannot parse.
    on_invalid: OnInvalidData,
}

impl<'g> CsafLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self {
            graph,
            // Only `Reject` is supported for now. Once the policy becomes an ingest
            // option, it will be passed in here instead.
            on_invalid: OnInvalidData::Reject,
        }
    }

    #[instrument(skip(self, csaf, tx), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        csaf: Csaf,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();
        let report = &warnings;

        let advisory_id = gen_identifier(&csaf, self.on_invalid, report)?;
        let labels = labels.into().add("type", "csaf");

        let information = advisory_information(&csaf, self.on_invalid, report)?;

        let advisory = match self
            .graph
            .ingest_advisory(&advisory_id, labels, digests, information, tx)
            .await?
        {
            Outcome::Existed(advisory) => {
                return Ok(IngestResult {
                    id: advisory.advisory.id.to_string(),
                    document_id: Some(advisory_id),
                    duplicate: true,
                    warnings: warnings.into(),
                    validation: Vec::new(),
                });
            }
            Outcome::Added(advisory) => advisory,
        };

        // Batch create all vulnerabilities first
        let mut vuln_creator = VulnerabilityCreator::new();
        for vuln in &csaf.vulnerabilities {
            if let Some(cve_id) = &vuln.cve {
                vuln_creator.add(cve_id.as_str(), ());
            }
        }
        vuln_creator.create(tx).await?;

        // Then process each vulnerability for linking and product status
        for vuln in &csaf.vulnerabilities {
            self.ingest_vulnerability(&csaf, &advisory, vuln, report, tx)
                .await?;
        }

        let mut creator = ScoreCreator::new(advisory.advisory.id);
        extract_scores(&csaf, &mut creator);
        creator.create(tx).await?;

        Ok(IngestResult {
            id: advisory.advisory.id.to_string(),
            document_id: Some(advisory_id),
            warnings: warnings.into(),
            duplicate: false,
            validation: Vec::new(),
        })
    }

    #[instrument(skip_all,
        fields(
            csaf=csaf.document.tracking.id.as_str(),
            cve=?vulnerability.cve
        )
    )]
    async fn ingest_vulnerability<C: ConnectionTrait>(
        &self,
        csaf: &Csaf,
        advisory: &AdvisoryContext<'_>,
        vulnerability: &Vulnerability,
        report: &dyn ReportSink,
        connection: &C,
    ) -> Result<(), Error> {
        let Some(cve_id) = &vulnerability.cve else {
            return Ok(());
        };

        // Vulnerability already created in batch, just link it
        let discovery_date = match vulnerability.discovery_date.as_deref() {
            Some(date) => self.on_invalid.validate(value::date(date), report)?,
            None => None,
        };
        let release_date = match vulnerability.release_date.as_deref() {
            Some(date) => self.on_invalid.validate(value::date(date), report)?,
            None => None,
        };

        let advisory_vulnerability = advisory
            .link_to_vulnerability(
                cve_id.as_str(),
                Some(AdvisoryVulnerabilityInformation {
                    title: vulnerability.title.as_ref().map(|title| title.to_string()),
                    summary: None,
                    description: None,
                    reserved_date: None,
                    discovery_date,
                    release_date,
                    cwes: vulnerability
                        .cwe
                        .as_ref()
                        .map(|cwe| vec![cwe.id.to_string()]),
                }),
                connection,
            )
            .await?;

        if let Some(product_status) = &vulnerability.product_status {
            self.ingest_product_statuses(
                csaf,
                &advisory_vulnerability,
                product_status,
                &vulnerability.remediations,
                report,
                connection,
            )
            .await?;
        }

        Ok(())
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    async fn ingest_product_statuses<C: ConnectionTrait>(
        &self,
        csaf: &Csaf,
        advisory_vulnerability: &AdvisoryVulnerabilityContext<'_>,
        product_status: &ProductStatus,
        remediations: &[Remediation],
        report: &dyn ReportSink,
        connection: &C,
    ) -> Result<(), Error> {
        let mut creator = StatusCreator::new(
            csaf,
            advisory_vulnerability.advisory_vulnerability.advisory_id,
            advisory_vulnerability
                .advisory_vulnerability
                .vulnerability_id
                .clone(),
        );

        creator.add_all(&product_status.fixed, "fixed", self.on_invalid, report)?;
        creator.add_all(
            &product_status.first_fixed,
            "first_fixed",
            self.on_invalid,
            report,
        )?;
        creator.add_all(
            &product_status.first_affected,
            "first_affected",
            self.on_invalid,
            report,
        )?;
        creator.add_all(
            &product_status.last_affected,
            "last_affected",
            self.on_invalid,
            report,
        )?;
        creator.add_all(
            &product_status.known_not_affected,
            "not_affected",
            self.on_invalid,
            report,
        )?;
        creator.add_all(
            &product_status.known_affected,
            "affected",
            self.on_invalid,
            report,
        )?;
        creator.add_all(
            &product_status.recommended,
            "recommended",
            self.on_invalid,
            report,
        )?;
        creator.add_all(
            &product_status.under_investigation,
            "under_investigation",
            self.on_invalid,
            report,
        )?;

        let product_id_mapping = creator.create(self.graph, connection).await?;

        let mut remediation_creator = RemediationCreator::new(
            advisory_vulnerability.advisory_vulnerability.advisory_id,
            advisory_vulnerability
                .advisory_vulnerability
                .vulnerability_id
                .clone(),
            product_id_mapping,
        );

        for remediation in remediations {
            remediation_creator.add(remediation);
        }

        remediation_creator.create(connection).await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        graph::Graph,
        service::advisory::test::{AssertScore, assert_scores},
    };
    use hex::ToHex;
    use rstest::rstest;
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::{
        advisory_vulnerability_score::{ScoreType, Severity},
        version_scheme::VersionScheme,
    };
    use trustify_test_context::{TrustifyContext, document, document_bytes};
    use uuid::Uuid;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();

        let tx = ctx.db.begin().await?;

        let (csaf, digests): (Csaf, _) = document("csaf/CVE-2023-20862.json").await?;
        let loader = CsafLoader::new(&graph);
        loader
            .load(("file", "CVE-2023-20862.json"), csaf, &digests, &tx)
            .await?;

        tx.commit().await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2023-20862", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        assert!(loaded_advisory.advisory.issuer_id.is_some());

        let loaded_advisory_vulnerabilities = loaded_advisory.vulnerabilities(&ctx.db).await?;
        assert_eq!(1, loaded_advisory_vulnerabilities.len());
        // let loaded_advisory_vulnerability = &loaded_advisory_vulnerabilities[0];

        // let affected_assertions = loaded_advisory_vulnerability
        //     .affected_assertions(())
        //     .await?;
        // assert_eq!(1, affected_assertions.assertions.len());

        // let affected_assertion = affected_assertions.assertions.get("pkg:cargo/hyper");
        // assert!(affected_assertion.is_some());

        // let affected_assertion = &affected_assertion.unwrap()[0];
        // assert!(
        //     matches!( affected_assertion, Assertion::Affected {start_version,end_version}
        //         if start_version == "0.0.0-0"
        //         && end_version == "0.14.10"
        //     )
        // );

        // let fixed_assertions = loaded_advisory_vulnerability.fixed_assertions(()).await?;
        // assert_eq!(1, fixed_assertions.assertions.len());

        // let fixed_assertion = fixed_assertions.assertions.get("pkg:cargo/hyper");
        // assert!(fixed_assertion.is_some());

        // let fixed_assertion = fixed_assertion.unwrap();
        // assert_eq!(1, fixed_assertion.len());

        // let fixed_assertion = &fixed_assertion[0];
        // assert!(matches!( fixed_assertion, Assertion::Fixed{version }
        //     if version == "0.14.10"
        // ));

        assert_scores(
            &ctx.db,
            loaded_advisory.advisory.id,
            [AssertScore {
                vulnerability_id: "CVE-2023-20862",
                r#type: ScoreType::V3_1,
                severity: Severity::Medium,
                vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                score: 6.3,
            }],
        )
        .await?;

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn multiple_vulnerabilities(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/rhsa-2024_3666.json").await?;
        ctx.db
            .transaction(async |tx| loader.load(("source", "test"), csaf, &digests, tx).await)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-23672", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        assert!(loaded_advisory.advisory.issuer_id.is_some());

        let loaded_advisory_vulnerabilities = loaded_advisory.vulnerabilities(&ctx.db).await?;
        assert_eq!(2, loaded_advisory_vulnerabilities.len());

        assert_scores(
            &ctx.db,
            loaded_advisory.advisory.id,
            [
                AssertScore {
                    vulnerability_id: "CVE-2024-23672",
                    r#type: ScoreType::V3_1,
                    severity: Severity::High,
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    score: 7.5,
                },
                AssertScore {
                    vulnerability_id: "CVE-2024-24549",
                    r#type: ScoreType::V3_1,
                    severity: Severity::High,
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    score: 7.5,
                },
            ],
        )
        .await?;

        Ok(())
    }
    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn product_status(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/cve-2023-0044.json").await?;
        ctx.db
            .transaction(async |tx| loader.load(("source", "test"), csaf, &digests, tx).await)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2023-0044", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        assert!(loaded_advisory.advisory.issuer_id.is_some());

        let loaded_advisory_vulnerabilities = loaded_advisory.vulnerabilities(&ctx.db).await?;
        assert_eq!(1, loaded_advisory_vulnerabilities.len());

        assert_scores(
            &ctx.db,
            loaded_advisory.advisory.id,
            [AssertScore {
                vulnerability_id: "CVE-2023-0044",
                r#type: ScoreType::V3_1,
                severity: Severity::Medium,
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                score: 5.3,
            }],
        )
        .await?;

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn remediations(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use trustify_entity::{remediation, remediation_product_status};

        let graph = Graph::new();
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/cve-2023-0044.json").await?;
        loader
            .load(("source", "test"), csaf, &digests, &ctx.db)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2023-0044", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();
        let advisory_id = loaded_advisory.advisory.id;

        let remediations = remediation::Entity::find()
            .filter(remediation::Column::AdvisoryId.eq(advisory_id))
            .filter(remediation::Column::VulnerabilityId.eq("CVE-2023-0044"))
            .all(&ctx.db)
            .await?;

        assert_eq!(4, remediations.len());

        let vendor_fix_remediations: Vec<_> = remediations
            .iter()
            .filter(|r| r.category == remediation::RemediationCategory::VendorFix)
            .collect();
        assert_eq!(2, vendor_fix_remediations.len());

        let workaround_remediations: Vec<_> = remediations
            .iter()
            .filter(|r| r.category == remediation::RemediationCategory::Workaround)
            .collect();
        assert_eq!(1, workaround_remediations.len());

        let none_available_remediations: Vec<_> = remediations
            .iter()
            .filter(|r| r.category == remediation::RemediationCategory::NoneAvailable)
            .collect();
        assert_eq!(1, none_available_remediations.len());

        let workaround = &workaround_remediations[0];
        assert_eq!(
            workaround.details.as_deref(),
            Some("This attack can be prevented with the Quarkus CSRF Prevention feature.")
        );

        let workaround_product_status_links = remediation_product_status::Entity::find()
            .filter(remediation_product_status::Column::RemediationId.eq(workaround.id))
            .all(&ctx.db)
            .await?;
        assert_eq!(12, workaround_product_status_links.len());

        let none_available = &none_available_remediations[0];
        assert_eq!(none_available.details.as_deref(), Some("Affected"));

        for vendor_fix in &vendor_fix_remediations {
            assert!(vendor_fix.url.is_some());
            assert!(
                vendor_fix
                    .url
                    .as_ref()
                    .unwrap()
                    .starts_with("https://access.redhat.com/errata/")
            );
        }

        let total_product_status_links = remediation_product_status::Entity::find()
            .all(&ctx.db)
            .await?;
        assert_eq!(
            15,
            total_product_status_links.len(),
            "Expected remediation to be linked to 15 product status's"
        );

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn remediations_with_purls(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use trustify_entity::{remediation, remediation_purl_status};

        let graph = Graph::new();
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/rhsa-2024_3666.json").await?;
        loader
            .load(("source", "test"), csaf, &digests, &ctx.db)
            .await?;

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();
        let advisory_id = loaded_advisory.advisory.id;

        let remediations = remediation::Entity::find()
            .filter(remediation::Column::AdvisoryId.eq(advisory_id))
            .all(&ctx.db)
            .await?;
        assert_eq!(4, remediations.len());

        let vendor_fix = remediations
            .iter()
            .find(|r| r.category == remediation::RemediationCategory::VendorFix);
        assert!(vendor_fix.is_some());

        let vendor_fix = vendor_fix.unwrap();
        let purl_status_links = remediation_purl_status::Entity::find()
            .filter(remediation_purl_status::Column::RemediationId.eq(vendor_fix.id))
            .all(&ctx.db)
            .await?;

        // All 9 original qualified PURLs retain separate fixed statements and remediation
        // links, including the two which share a base identity. Implied affected ranges
        // are still derived by correlation rather than stored.
        assert_eq!(
            9,
            purl_status_links.len(),
            "Expected vendor_fix remediation to be linked to all 9 qualified PURL statements"
        );

        Ok(())
    }

    /// Only what the document states is stored: Red Hat's fixed versions don't imply additional
    /// "affected" ranges (those are derived by correlation).
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn redhat_stores_stated_statuses_only(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use sea_orm::{
            ColumnTrait, EntityTrait, JoinType, QueryFilter, QuerySelect, RelationTrait,
        };
        use trustify_entity::{purl_status, status};

        let graph = Graph::new();
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/rhsa-2024_3666.json").await?;
        loader
            .load(("source", "test"), csaf, &digests, &ctx.db)
            .await?;

        let advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?
            .expect("advisory must exist")
            .advisory;
        assert_eq!(
            advisory.publisher_namespace.as_deref(),
            Some("https://www.redhat.com")
        );

        let mut slugs: Vec<String> = purl_status::Entity::find()
            .select_only()
            .column(status::Column::Slug)
            .join(JoinType::InnerJoin, purl_status::Relation::Status.def())
            .filter(purl_status::Column::AdvisoryId.eq(advisory.id))
            .distinct()
            .into_tuple()
            .all(&ctx.db)
            .await?;
        slugs.sort();
        assert_eq!(slugs, vec!["fixed".to_string()]);

        Ok(())
    }

    /// All product statuses of CSAF are stored as stated, including those stating a single
    /// version (`first_fixed`, `first_affected`, `last_affected`).
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn stores_all_product_statuses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        use sea_orm::{EntityTrait, JoinType, QueryOrder, QuerySelect, RelationTrait};
        use trustify_entity::{purl_status, status, version_range};

        let graph = Graph::new();
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/statuses/first-last.json").await?;
        loader
            .load(("source", "test"), csaf, &digests, &ctx.db)
            .await?;

        let statuses: Vec<(String, String, Option<String>, Option<String>)> =
            purl_status::Entity::find()
                .select_only()
                .column(purl_status::Column::VulnerabilityId)
                .column(status::Column::Slug)
                .column(version_range::Column::LowVersion)
                .column(version_range::Column::HighVersion)
                .join(JoinType::InnerJoin, purl_status::Relation::Status.def())
                .join(
                    JoinType::InnerJoin,
                    purl_status::Relation::VersionRange.def(),
                )
                .order_by_asc(purl_status::Column::VulnerabilityId)
                .into_tuple()
                .all(&ctx.db)
                .await?;

        let version = || Some("1:1.1.1k-9.el8_6".to_string());
        assert_eq!(
            statuses,
            [
                ("CVE-2099-30001", "first_fixed"),
                ("CVE-2099-30002", "first_affected"),
                ("CVE-2099-30003", "last_affected"),
                ("CVE-2099-30004", "under_investigation"),
            ]
            .map(|(vulnerability, slug)| (
                vulnerability.to_string(),
                slug.to_string(),
                version(),
                version()
            ))
        );

        Ok(())
    }

    /// Ingest a fixture with the value at `pointer` replaced by an invalid one.
    ///
    /// The patch is applied to the raw JSON so that the value still has to survive
    /// csaf-rs' own schema validation, proving it reaches trustify's parsing.
    async fn load_patched(
        ctx: &TrustifyContext,
        fixture: &str,
        pointer: &str,
        replacement: &str,
        on_invalid: OnInvalidData,
    ) -> Result<IngestResult, Error> {
        let data = document_bytes(fixture).await.expect("fixture loads");

        let mut doc: serde_json::Value = serde_json::from_slice(&data)?;
        *doc.pointer_mut(pointer)
            .expect("fixture has the patched value") = replacement.into();

        let data = serde_json::to_vec(&doc)?;
        let digests = Digests::digest(&data);
        let csaf: Csaf = serde_json::from_slice(&data)?;

        let graph = Graph::new();
        CsafLoader {
            graph: &graph,
            on_invalid,
        }
        .load(("source", "test"), csaf, &digests, &ctx.db)
        .await
    }

    /// A value trustify cannot parse rejects the document, rather than being skipped.
    ///
    /// Each replacement satisfies the CSAF schema — so csaf-rs accepts it and it reaches
    /// our own parsing — while being invalid for the type it represents:
    ///
    /// * `pkg:cargo/ns/name@1.0` is not a valid purl, because `cargo` prohibits a namespace.
    ///   This is the case that previously got recorded silently as a *package name*.
    /// * `cpe:/a:vendor:product%zz` is not a valid CPE, because `%zz` is not a percent escape. (An
    ///   invalid language tag is no longer rejected, but dropped, see `trustify_common::cpe`.)
    /// * `prior to 4.2` is neither vers nor vls, which is all a `product_version_range` may hold.
    /// * dates and the publisher namespace are plain strings in CSAF, so anything reaches us.
    #[test_context(TrustifyContext)]
    #[rstest]
    #[case::purl(
        "csaf/rhsa-2024_3666.json",
        "/product_tree/branches/0/branches/1/branches/0/product/product_identification_helper/purl",
        "pkg:cargo/ns/name@1.0",
        "invalid purl"
    )]
    #[case::cpe(
        "csaf/cve-2023-0044.json",
        "/product_tree/branches/0/branches/0/product/product_identification_helper/cpe",
        "cpe:/a:vendor:product%zz",
        "invalid cpe"
    )]
    #[case::range(
        "csaf/ranges/vers-and-vls.json",
        LIB_RANGE,
        "prior to 4.2",
        "invalid version range"
    )]
    #[case::date(
        "csaf/cve-2023-0044.json",
        "/document/tracking/initial_release_date",
        "not-a-date",
        "invalid date"
    )]
    #[case::namespace(
        "csaf/cve-2023-0044.json",
        "/document/publisher/namespace",
        "not a url",
        "invalid url"
    )]
    #[test_log::test(tokio::test)]
    async fn reject_invalid_value(
        ctx: &TrustifyContext,
        #[case] fixture: &str,
        #[case] pointer: &str,
        #[case] replacement: &str,
        #[case] expected: &str,
    ) -> Result<(), anyhow::Error> {
        let err = load_patched(ctx, fixture, pointer, replacement, OnInvalidData::Reject)
            .await
            .expect_err("must reject an invalid value");

        assert!(
            matches!(&err, Error::InvalidContent(_)),
            "expected InvalidContent, got {err:?}"
        );
        assert!(err.to_string().contains(expected), "got {err}");

        Ok(())
    }

    /// The `product_version_range` of the vls product in `csaf/ranges/vers-and-vls.json`.
    const LIB_RANGE: &str = "/product_tree/branches/0/branches/1/branches/0/name";

    /// A stored purl status: base purl name, version range (scheme, low, low inclusive, high,
    /// high inclusive) and status.
    type StatedPurlStatus = (
        String,
        VersionScheme,
        Option<String>,
        Option<bool>,
        Option<String>,
        Option<bool>,
        String,
    );

    /// All purl statuses an advisory states, sorted by name and status.
    async fn stated_purl_statuses(
        ctx: &TrustifyContext,
        advisory_id: &str,
    ) -> Result<Vec<StatedPurlStatus>, anyhow::Error> {
        use sea_orm::{
            ColumnTrait, EntityTrait, JoinType, QueryFilter, QuerySelect, RelationTrait,
        };
        use trustify_entity::{base_purl, purl_status, status, version_range};

        let mut result: Vec<StatedPurlStatus> = purl_status::Entity::find()
            .select_only()
            .column(base_purl::Column::Name)
            .column(version_range::Column::VersionSchemeId)
            .column(version_range::Column::LowVersion)
            .column(version_range::Column::LowInclusive)
            .column(version_range::Column::HighVersion)
            .column(version_range::Column::HighInclusive)
            .column(status::Column::Slug)
            .join(JoinType::InnerJoin, purl_status::Relation::BasePurl.def())
            .join(
                JoinType::InnerJoin,
                purl_status::Relation::VersionRange.def(),
            )
            .join(JoinType::InnerJoin, purl_status::Relation::Status.def())
            .filter(purl_status::Column::AdvisoryId.eq(advisory_id.parse::<Uuid>()?))
            .into_tuple()
            .all(&ctx.db)
            .await?;
        result.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.6.cmp(&b.6)));
        Ok(result)
    }

    /// A version range is stored as stated: vers with its scheme, vls without one, and only for
    /// the purl of its own product. For a relationship, the platform is neither a subject of the
    /// status, nor does its range constrain the component.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ranges_as_stated(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let result = ctx.ingest_document("csaf/ranges/vers-and-vls.json").await?;
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);

        assert_eq!(
            stated_purl_statuses(ctx, &result.id).await?,
            vec![
                (
                    "example-app".to_string(),
                    VersionScheme::Semver,
                    None,
                    Some(false),
                    Some("2.0.0".to_string()),
                    Some(false),
                    "affected".to_string(),
                ),
                (
                    "example-lib".to_string(),
                    VersionScheme::Vls,
                    None,
                    Some(false),
                    Some("4.2".to_string()),
                    Some(false),
                    "affected".to_string(),
                ),
            ]
        );

        Ok(())
    }

    /// A range which can't be parsed, and is skipped by the policy, drops the purls of its
    /// product, rather than claiming all versions.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn invalid_range_skipped(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let result = load_patched(
            ctx,
            "csaf/ranges/vers-and-vls.json",
            LIB_RANGE,
            "prior to 4.2",
            OnInvalidData::Warn,
        )
        .await?;

        assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
        assert!(
            result.warnings[0].starts_with("invalid version range 'prior to 4.2'"),
            "{:?}",
            result.warnings
        );
        assert_eq!(
            stated_purl_statuses(ctx, &result.id).await?,
            vec![(
                "example-app".to_string(),
                VersionScheme::Semver,
                None,
                Some(false),
                Some("2.0.0".to_string()),
                Some(false),
                "affected".to_string(),
            )]
        );

        Ok(())
    }

    /// A status stated for a relationship is stored with its context: the platform, with its
    /// identifiers, name and the relationship category. A product which isn't a relationship has
    /// no context.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn relationship_context(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use trustify_entity::{
            assertion_context::{self, AssertionContextCategory},
            assertion_context_identifier::{self, ContextIdentifierKind},
            base_purl, purl_status,
        };

        let result = ctx.ingest_document("csaf/ranges/vers-and-vls.json").await?;
        let advisory_id = result.id.parse::<Uuid>()?;

        let mut statuses = purl_status::Entity::find()
            .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
            .find_also_related(base_purl::Entity)
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|(status, purl)| {
                (
                    purl.map(|purl| purl.name).unwrap_or_default(),
                    status.assertion_context_id,
                )
            })
            .collect::<Vec<_>>();
        statuses.sort();

        let [(app, Some(context_id)), (lib, None)] = statuses.as_slice() else {
            panic!("unexpected statuses: {statuses:?}");
        };
        assert_eq!((app.as_str(), lib.as_str()), ("example-app", "example-lib"));

        let context = assertion_context::Entity::find_by_id(*context_id)
            .one(&ctx.db)
            .await?
            .expect("context must exist");
        assert_eq!(
            (context.category, context.name.as_str()),
            (
                Some(AssertionContextCategory::InstalledOn),
                "Example Platform < 3.0.0"
            )
        );

        let identifiers = assertion_context_identifier::Entity::find()
            .filter(assertion_context_identifier::Column::ContextId.eq(*context_id))
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|identifier| (identifier.kind, identifier.value))
            .collect::<Vec<_>>();
        assert_eq!(
            identifiers,
            [(
                ContextIdentifierKind::Purl,
                "pkg:npm/example-platform".to_string()
            )]
        );

        Ok(())
    }
}
