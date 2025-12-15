use crate::graph::cvss::ScoreCreator;
use crate::service::advisory::csaf::extract_scores;
use crate::{
    graph::{
        Graph,
        advisory::{
            AdvisoryContext, AdvisoryInformation, AdvisoryVulnerabilityInformation,
            advisory_vulnerability::AdvisoryVulnerabilityContext,
        },
        vulnerability::creator::VulnerabilityCreator,
    },
    model::IngestResult,
    service::{
        Error, Warnings,
        advisory::csaf::{RemediationCreator, StatusCreator, util::gen_identifier},
    },
};
use csaf::{
    Csaf,
    vulnerability::{ProductStatus, Remediation, Vulnerability},
};
use cvss::v3::CvssV3;
use hex::ToHex;
use sbom_walker::report::ReportSink;
use sea_orm::{ConnectionTrait, TransactionTrait};
use semver::Version;
use std::{fmt::Debug, str::FromStr};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id};
use trustify_cvss::cvss3::Cvss3Base;
use trustify_entity::labels::Labels;

struct Information<'a>(&'a Csaf);

impl<'a> From<Information<'a>> for AdvisoryInformation {
    fn from(value: Information<'a>) -> Self {
        let value = value.0;
        Self {
            id: value.document.tracking.id.clone(),
            // TODO: consider failing if the version doesn't parse
            version: parse_csaf_version(value),
            title: Some(value.document.title.clone()),
            issuer: Some(value.document.publisher.name.clone()),
            published: OffsetDateTime::from_unix_timestamp(
                value.document.tracking.initial_release_date.timestamp(),
            )
            .ok(),
            modified: OffsetDateTime::from_unix_timestamp(
                value.document.tracking.current_release_date.timestamp(),
            )
            .ok(),
            withdrawn: None,
        }
    }
}

/// Parse a CSAF tracking version.
///
/// This can be either a semantic version or a plain number. In case of a plain number, we use
/// this as a major version.
fn parse_csaf_version(csaf: &Csaf) -> Option<Version> {
    // TODO: consider checking individual tracking records too
    let version = &csaf.document.tracking.version;
    if version.contains('.') {
        csaf.document.tracking.version.parse().ok()
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
}

impl<'g> CsafLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, csaf), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        csaf: Csaf,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();

        let tx = self.graph.db.begin().await?;

        let advisory_id = gen_identifier(&csaf);
        let labels = labels.into().add("type", "csaf");

        let sha256 = digests.sha256.encode_hex::<String>();
        if let Some(found) = self.graph.get_advisory_by_digest(&sha256, &tx).await? {
            // we already have the exact same document.
            return Ok(IngestResult {
                id: Id::Uuid(found.advisory.id),
                document_id: Some(advisory_id),
                warnings: warnings.into(),
            });
        }

        let advisory = self
            .graph
            .ingest_advisory(&advisory_id, labels, digests, Information(&csaf), &tx)
            .await?;

        // Batch create all vulnerabilities first
        let mut vuln_creator = VulnerabilityCreator::new();
        for vuln in csaf.vulnerabilities.iter().flatten() {
            if let Some(cve_id) = &vuln.cve {
                vuln_creator.add(cve_id, ());
            }
        }
        vuln_creator.create(&tx).await?;

        // Then process each vulnerability for linking and product status
        for vuln in csaf.vulnerabilities.iter().flatten() {
            self.ingest_vulnerability(&csaf, &advisory, vuln, &warnings, &tx)
                .await?;
        }

        let mut creator = ScoreCreator::new(advisory.advisory.id);
        extract_scores(&csaf, &mut creator);
        creator.create(&tx).await?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(advisory.advisory.id),
            document_id: Some(advisory_id),
            warnings: warnings.into(),
        })
    }

    #[instrument(skip_all,
        fields(
            csaf=csaf.document.tracking.id,
            cve=vulnerability.cve
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
        let advisory_vulnerability = advisory
            .link_to_vulnerability(
                cve_id,
                Some(AdvisoryVulnerabilityInformation {
                    title: vulnerability.title.clone(),
                    summary: None,
                    description: None,
                    reserved_date: None,
                    discovery_date: vulnerability.discovery_date.and_then(|date| {
                        OffsetDateTime::from_unix_timestamp(date.timestamp()).ok()
                    }),
                    release_date: vulnerability.release_date.and_then(|date| {
                        OffsetDateTime::from_unix_timestamp(date.timestamp()).ok()
                    }),
                    cwes: vulnerability.cwe.as_ref().map(|cwe| vec![cwe.id.clone()]),
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
                connection,
            )
            .await?;
        }

        for score in vulnerability.scores.iter().flatten() {
            if let Some(cvss_v3) = &score.cvss_v3 {
                match serde_json::from_value::<CvssV3>(cvss_v3.clone()) {
                    Ok(cvss) => match Cvss3Base::from_str(&cvss.vector_string) {
                        Ok(cvss3) => {
                            log::debug!("{cvss3:?}");
                            advisory_vulnerability
                                .ingest_cvss3_score(cvss3, connection)
                                .await?;
                        }
                        Err(err) => {
                            let msg = format!("Unable to parse CVSS3: {err:#?}");
                            log::info!("{msg}");
                            report.error(msg);
                        }
                    },
                    Err(err) => {
                        let msg = format!("Unable to deserialize CVSS3 JSON: {err:#?}");
                        log::info!("{msg}");
                        report.error(msg);
                    }
                }
            }
        }

        Ok(())
    }

    #[instrument(skip_all, err)]
    async fn ingest_product_statuses<C: ConnectionTrait>(
        &self,
        csaf: &Csaf,
        advisory_vulnerability: &AdvisoryVulnerabilityContext<'_>,
        product_status: &ProductStatus,
        remediations: &Option<Vec<Remediation>>,
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

        creator.add_all(&product_status.fixed, "fixed");
        creator.add_all(&product_status.known_not_affected, "not_affected");
        creator.add_all(&product_status.known_affected, "affected");

        let product_id_mapping = creator.create(self.graph, connection).await?;

        if let Some(remediations) = remediations {
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
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::ToHex;

    use crate::graph::Graph;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::{TrustifyContext, document};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());

        let (csaf, digests): (Csaf, _) = document("csaf/CVE-2023-20862.json").await?;
        let loader = CsafLoader::new(&graph);
        loader
            .load(("file", "CVE-2023-20862.json"), csaf, &digests)
            .await?;

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

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2023-20862", &ctx.db)
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(&ctx.db).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        );

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn multiple_vulnerabilities(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/rhsa-2024_3666.json").await?;
        loader.load(("source", "test"), csaf, &digests).await?;

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

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2024-23672", &ctx.db)
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(&ctx.db).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        );

        Ok(())
    }
    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn product_status(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/cve-2023-0044.json").await?;
        loader.load(("source", "test"), csaf, &digests).await?;

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

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2023-0044", &ctx.db)
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(&ctx.db).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        );

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn remediations(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use trustify_entity::{remediation, remediation_product_status};

        let graph = Graph::new(ctx.db.clone());
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/cve-2023-0044.json").await?;
        loader.load(("source", "test"), csaf, &digests).await?;

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

        let graph = Graph::new(ctx.db.clone());
        let loader = CsafLoader::new(&graph);

        let (csaf, digests): (Csaf, _) = document("csaf/rhsa-2024_3666.json").await?;
        loader.load(("source", "test"), csaf, &digests).await?;

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
}
