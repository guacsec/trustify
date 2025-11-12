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
        advisory::csaf::{StatusCreator, util::gen_identifier},
    },
};
use csaf::{
    Csaf,
    vulnerability::{ProductStatus, Vulnerability},
};
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
            self.ingest_product_statuses(csaf, &advisory_vulnerability, product_status, connection)
                .await?;
        }

        for score in vulnerability.scores.iter().flatten() {
            if let Some(v3) = &score.cvss_v3 {
                match Cvss3Base::from_str(&v3.to_string()) {
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

        creator.create(self.graph, connection).await?;

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
}
