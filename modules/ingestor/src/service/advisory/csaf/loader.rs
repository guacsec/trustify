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
    use trustify_entity::advisory_vulnerability_score::{ScoreType, Severity};
    use trustify_test_context::{TrustifyContext, document, document_bytes};

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

        // There are 9 purls in rhsa-2024_3666 and 2 vulnerabilities, but 2 purls share a base
        // resulting in 8 x 2 = 16
        assert_eq!(
            16,
            purl_status_links.len(),
            "Expected vendor_fix remediation to be linked to 16 purl statuses"
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
    ) -> Result<IngestResult, Error> {
        let data = document_bytes(fixture).await.expect("fixture loads");

        let mut doc: serde_json::Value = serde_json::from_slice(&data)?;
        *doc.pointer_mut(pointer)
            .expect("fixture has the patched value") = replacement.into();

        let data = serde_json::to_vec(&doc)?;
        let digests = Digests::digest(&data);
        let csaf: Csaf = serde_json::from_slice(&data)?;

        CsafLoader::new(&Graph::new())
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
    /// * `cpe:/a:vendor:product:1:2:3:4` is not a valid CPE, because `4` is not a language tag.
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
        "cpe:/a:vendor:product:1:2:3:4",
        "invalid cpe"
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
        let err = load_patched(ctx, fixture, pointer, replacement)
            .await
            .expect_err("must reject an invalid value");

        assert!(
            matches!(&err, Error::InvalidContent(_)),
            "expected InvalidContent, got {err:?}"
        );
        assert!(err.to_string().contains(expected), "got {err}");

        Ok(())
    }
}
