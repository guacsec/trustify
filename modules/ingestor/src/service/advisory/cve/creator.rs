//! Collects the statements of a CVE record about its vulnerability, and creates them.
//!
//! The identifier-like fields of an `affected` entry (`packageURL`, `collectionURL` and
//! `packageName`, `cpes`) are synonyms of the same software: its `versions` and `defaultStatus`
//! apply to each of them (see the CVE schema's RFD "Supporting Package URLs"). The CPEs are stored
//! as the vendor/product identity (version ANY).
//!
//! The CPE applicability statements (`cpeApplicability`) state the vulnerable CPEs.
//!
//! The PURL statements go to `purl_status`. The CPE statements go to `advisory_vulnerability_cpe`,
//! which the correlation engine matches, and (without defaults, which they don't evaluate) to
//! `cpe_status` for the fundamental APIs.

use crate::{
    graph::{
        advisory::{
            cpe_assertion::{CpeAssertion, CpeAssertionCreator},
            version::{VersionInfo, VersionSpec},
        },
        cpe::CpeCreator,
        cpe_status_creator::{CpeStatusCreator, CpeStatusEntry},
        error::Error,
        purl::{
            self,
            status_creator::{PurlStatusCreator, PurlStatusEntry},
        },
    },
    service::{
        Warnings,
        advisory::{
            cve::statement::{Statement, default_statement, listed_statements, package_purl},
            nvd::{loader::version_spec, schema::Configuration},
        },
    },
};
use cve::common::Product;
use sea_orm::{ConnectionTrait, DbErr, TransactionTrait};
use std::{collections::HashSet, str::FromStr};
use trustify_common::cpe::{Component, Cpe};
use trustify_entity::{correlation_evidence::AssertionStatus, version_scheme::VersionScheme};
use uuid::Uuid;

/// The statements of a CVE record about its vulnerability.
pub struct StatementCreator<'w> {
    advisory_id: Uuid,
    vulnerability_id: String,
    warnings: &'w Warnings,
    base_purls: HashSet<trustify_common::purl::Purl>,
    purl_statuses: PurlStatusCreator,
    cpes: HashSet<Cpe>,
    cpe_statuses: CpeStatusCreator,
    cpe_assertions: CpeAssertionCreator,
}

impl<'w> StatementCreator<'w> {
    pub fn new(advisory_id: Uuid, vulnerability_id: String, warnings: &'w Warnings) -> Self {
        Self {
            advisory_id,
            vulnerability_id,
            warnings,
            base_purls: HashSet::new(),
            purl_statuses: PurlStatusCreator::new(),
            cpes: HashSet::new(),
            cpe_statuses: CpeStatusCreator::new(),
            cpe_assertions: CpeAssertionCreator::new(advisory_id),
        }
    }

    /// Add the statements of an `affected` entry.
    pub async fn add_product<C: ConnectionTrait + TransactionTrait>(
        &mut self,
        product: &Product,
        connection: &C,
    ) -> Result<(), DbErr> {
        let listed = listed_statements(product, self.warnings, connection).await?;
        let default = default_statement(product);

        self.add_package(product, &listed, default.as_ref());
        self.add_product_cpes(product, &listed, default.as_ref());

        Ok(())
    }

    /// The statements of the entry's package, if it names one.
    fn add_package(
        &mut self,
        product: &Product,
        listed: &[Statement],
        default: Option<&Statement>,
    ) {
        let Some(purl) = package_purl(product, self.warnings) else {
            return;
        };
        self.base_purls.insert(purl.clone());
        for statement in listed.iter().chain(default) {
            self.purl_statuses.add(PurlStatusEntry {
                advisory_id: self.advisory_id,
                vulnerability_id: self.vulnerability_id.clone(),
                purl: purl.clone(),
                status: statement.status.to_string(),
                version_info: statement.version_info.clone(),
                context_cpe: None,
                context_id: None,
                default: statement.default,
            });
        }
    }

    /// The statements of the CPEs of an entry.
    fn add_product_cpes(
        &mut self,
        product: &Product,
        listed: &[Statement],
        default: Option<&Statement>,
    ) {
        for cpe in product
            .cpes
            .iter()
            .filter_map(|cpe| Cpe::from_str(cpe).ok())
        {
            let identity = cpe.with_any_version();

            let statements = match cpe.version() {
                // no versions listed: the default status of the CPE's version
                Component::Value(version) if product.versions.is_empty() => default
                    .map(|default| Statement {
                        version_info: VersionInfo {
                            scheme: VersionScheme::Generic,
                            spec: VersionSpec::Exact(version),
                        },
                        default: false,
                        ..default.clone()
                    })
                    .into_iter()
                    .collect(),
                _ => listed.iter().chain(default).cloned().collect::<Vec<_>>(),
            };

            for statement in statements {
                self.add_cpe(&identity, statement);
            }
        }
    }

    /// A CPE statement.
    fn add_cpe(&mut self, cpe: &Cpe, statement: Statement) {
        let status = match statement.status {
            "affected" => AssertionStatus::Affected,
            _ => AssertionStatus::NotAffected,
        };
        self.cpe_assertions.add(CpeAssertion {
            vulnerability_id: self.vulnerability_id.clone(),
            cpe: cpe.clone(),
            range: Some(statement.version_info.clone()),
            status,
            context: None,
            default: statement.default,
        });

        // the fundamental APIs don't evaluate defaults
        if !statement.default {
            self.cpes.insert(cpe.clone());
            self.cpe_statuses.add(CpeStatusEntry {
                advisory_id: self.advisory_id,
                vulnerability_id: self.vulnerability_id.clone(),
                cpe: cpe.clone(),
                status: statement.status.to_string(),
                version_info: statement.version_info,
                context_cpe: None,
            });
        }
    }

    /// Add the statements of a CPE applicability configuration.
    pub fn add_applicability(&mut self, configuration: &Configuration) {
        if configuration.negate || configuration.nodes.iter().any(|node| node.negate) {
            self.warnings.add(format!(
                "{}: ignoring a negated CPE applicability configuration",
                self.vulnerability_id
            ));
            return;
        }

        // the vulnerable CPEs; the non-vulnerable ones (e.g. the platform of an `AND`
        // configuration) don't scope them yet
        let matches = configuration.nodes.iter().flat_map(|node| &node.cpe_match);

        for cpe_match in matches.filter(|m| m.vulnerable) {
            let Ok(cpe) = Cpe::from_str(&cpe_match.criteria).inspect_err(|err| {
                self.warnings.add(format!(
                    "{}: ignoring the invalid CPE {:?}: {err}",
                    self.vulnerability_id, cpe_match.criteria
                ))
            }) else {
                continue;
            };

            let identity = cpe.with_any_version();
            match version_spec(cpe_match, &cpe) {
                // version bounds are ordered comparisons, as for NVD
                Some(spec) => self.add_cpe(
                    &identity,
                    Statement {
                        status: "affected",
                        version_info: VersionInfo {
                            scheme: VersionScheme::Semver,
                            spec,
                        },
                        default: false,
                    },
                ),
                // no version: all versions
                None => self.cpe_assertions.add(CpeAssertion {
                    vulnerability_id: self.vulnerability_id.clone(),
                    cpe: identity,
                    range: None,
                    status: AssertionStatus::Affected,
                    context: None,
                    default: false,
                }),
            }
        }
    }

    /// Create all statements.
    pub async fn create(self, connection: &impl ConnectionTrait) -> Result<(), Error> {
        purl::batch_create_base_purls(self.base_purls, connection).await?;
        self.purl_statuses.create(connection).await?;

        let mut cpes = CpeCreator::new();
        for cpe in self.cpes {
            cpes.add(cpe);
        }
        cpes.create(connection).await?;
        self.cpe_statuses.create(connection).await?;
        self.cpe_assertions.create(connection).await?;

        Ok(())
    }
}
