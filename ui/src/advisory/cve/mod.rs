//! The CVE specific view of an advisory: a CVE record (CVE JSON 5.x) of the CVE Program, parsed from
//! its source document.
//!
//! A record has the container of the CNA, which assigned the CVE ID, and those of ADPs (e.g. CISA)
//! enriching it. Each container may state the affected products (`affected`) and their CPE
//! applicability (`cpeApplicability`). See
//! <https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json>.

mod affected;
mod applicability;
mod overview;
mod references;

use super::none;
use ::cve::{
    Cve, Timestamp,
    common::{Description, Product, Reference},
    published::{AdpContainer, Metric},
};
use affected::AffectedTab;
use applicability::ApplicabilityTab;
use overview::Overview;
use patternfly_yew::prelude::*;
use references::ReferencesTab;
use serde::Deserialize;
use serde_json::Value;
use std::{ops::Deref, rc::Rc};
use yew::prelude::*;

/// The CVE specific tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CveTab {
    Overview,
    Affected,
    Applicability,
    References,
}

impl CveTab {
    pub const ALL: [Self; 4] = [
        Self::Overview,
        Self::Affected,
        Self::Applicability,
        Self::References,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Affected => "Affected",
            Self::Applicability => "CPE applicability",
            Self::References => "References",
        }
    }
}

/// A CPE applicability statement (`cpeApplicability`), in the CPE Applicability Language. The `cve`
/// crate doesn't model it.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Configuration {
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub nodes: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    #[serde(default)]
    pub version_start_including: Option<String>,
    #[serde(default)]
    pub version_start_excluding: Option<String>,
    #[serde(default)]
    pub version_end_including: Option<String>,
    #[serde(default)]
    pub version_end_excluding: Option<String>,
}

/// A container of the record: the CNA's, or an ADP's.
pub struct Container<'a> {
    /// The provider, e.g. `CISA-ADP`.
    pub provider: String,
    pub adp: bool,
    pub affected: &'a [Product],
    pub references: &'a [Reference],
    pub applicability: &'a [Configuration],
}

/// A parsed CVE record, and the CPE applicability of its containers (CNA first, then the ADPs).
pub struct CveRecord {
    pub cve: Cve,
    pub applicability: Vec<Vec<Configuration>>,
}

impl CveRecord {
    /// The containers, the CNA's first.
    pub fn containers(&self) -> Vec<Container<'_>> {
        let applicability = |n: usize| {
            self.applicability
                .get(n)
                .map(Vec::as_slice)
                .unwrap_or_default()
        };
        match &self.cve {
            Cve::Published(published) => {
                let cna = &published.containers.cna;
                let mut result = vec![Container {
                    provider: provider(cna.common.provider_metadata.short_name.as_deref(), "CNA"),
                    adp: false,
                    affected: &cna.affected,
                    references: &cna.references,
                    applicability: applicability(0),
                }];
                result.extend(published.containers.adp.iter().enumerate().map(
                    |(n, adp): (usize, &AdpContainer)| Container {
                        provider: provider(adp.provider_metadata.short_name.as_deref(), "ADP"),
                        adp: true,
                        affected: &adp.affected,
                        references: &adp.references,
                        applicability: applicability(n + 1),
                    },
                ));
                result
            }
            Cve::Rejected(rejected) => vec![Container {
                provider: provider(
                    rejected
                        .containers
                        .cna
                        .common
                        .provider_metadata
                        .short_name
                        .as_deref(),
                    "CNA",
                ),
                adp: false,
                affected: &[],
                references: &[],
                applicability: &[],
            }],
        }
    }

    /// The metrics of all containers, with their provider.
    pub fn metrics(&self) -> Vec<(String, &Metric)> {
        match &self.cve {
            Cve::Published(published) => {
                let cna = &published.containers.cna;
                let cna_provider =
                    provider(cna.common.provider_metadata.short_name.as_deref(), "CNA");
                cna.metrics
                    .iter()
                    .map(|metric| (cna_provider.clone(), metric))
                    .chain(published.containers.adp.iter().flat_map(|adp| {
                        let provider = provider(adp.provider_metadata.short_name.as_deref(), "ADP");
                        adp.metrics
                            .iter()
                            .map(move |metric| (provider.clone(), metric))
                    }))
                    .collect()
            }
            Cve::Rejected(_) => vec![],
        }
    }
}

fn provider(short_name: Option<&str>, fallback: &str) -> String {
    short_name.unwrap_or(fallback).to_string()
}

/// A shared [`CveRecord`], compared by identity.
#[derive(Clone)]
pub struct Doc(Rc<CveRecord>);

impl PartialEq for Doc {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl Deref for Doc {
    type Target = CveRecord;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Parse a CVE record, with the `cpeApplicability` of its containers.
fn parse(text: &str) -> Result<Doc, serde_json::Error> {
    let value = serde_json::from_str::<Value>(text)?;

    let containers = value.get("containers");
    let cna = containers.and_then(|c| c.get("cna"));
    let adp = containers
        .and_then(|c| c.get("adp"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    let applicability = cna
        .into_iter()
        .chain(adp)
        .map(|container| {
            container
                .get("cpeApplicability")
                .map(Vec::<Configuration>::deserialize)
                .transpose()
                .map(Option::unwrap_or_default)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let cve = serde_json::from_value(value)?;
    Ok(Doc(Rc::new(CveRecord { cve, applicability })))
}

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct CveViewProps {
    pub document: Rc<String>,
    pub tab: CveTab,
}

#[function_component(CveView)]
pub fn cve_view(props: &CveViewProps) -> Html {
    let parsed = use_memo(props.document.clone(), |doc| parse(doc));

    match &*parsed {
        Err(err) => html! {
            <Alert title="Failed to read the CVE record" r#type={AlertType::Danger} inline=true>
                <p>{ format!("Invalid CVE record: {err}") }</p>
            </Alert>
        },
        Ok(doc) => {
            let doc = doc.clone();
            match props.tab {
                CveTab::Overview => html!(<Overview {doc} />),
                CveTab::Affected => html!(<AffectedTab {doc} />),
                CveTab::Applicability => html!(<ApplicabilityTab {doc} />),
                CveTab::References => html!(<ReferencesTab {doc} />),
            }
        }
    }
}

/// A timestamp, or the placeholder.
fn timestamp(value: Option<Timestamp>) -> Html {
    value
        .map(|value| html!(value.assume_utc().to_string()))
        .unwrap_or_else(none)
}

/// The English description of a list, or the first.
fn english(descriptions: &[Description]) -> Option<&Description> {
    descriptions
        .iter()
        .find(|d| d.language.starts_with("en"))
        .or_else(|| descriptions.first())
}

/// A label for the provider of a container.
fn provider_label(container: &Container<'_>) -> Html {
    html! {
        <Label
            label={container.provider.clone()}
            color={if container.adp { Color::Purple } else { Color::Blue }}
            compact=true
        />
    }
}

#[cfg(test)]
mod test {
    use super::parse;

    const KERNEL: &str = include_str!(
        "../../../../etc/test-data/scenarios/S26_cve_cpe_applicability_kernel/cve/CVE-2024-26581.json"
    );

    /// The Linux kernel record (CVE-2024-26581) has `cpeApplicability` in the CNA container, and ADP
    /// containers.
    #[test]
    fn parse_record() {
        let doc = parse(KERNEL).expect("record parses");
        let containers = doc.containers();
        assert_eq!(
            containers
                .iter()
                .map(|c| (
                    c.provider.as_str(),
                    c.adp,
                    c.affected.len(),
                    c.applicability.len()
                ))
                .collect::<Vec<_>>(),
            [
                ("Linux", false, 2, 1),
                ("CISA-ADP", true, 0, 0),
                ("CVE", true, 0, 0)
            ]
        );
        assert_eq!(
            doc.applicability[0][0].nodes[0].cpe_match.len(),
            8,
            "the kernel ranges"
        );
    }
}
