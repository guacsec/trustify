//! The CSAF specific view of an advisory, parsed from its source document.

mod index;
mod notes;
mod overview;
mod product_tree;
mod products;
mod status;
mod vulnerabilities;

use ::csaf::schema::csaf2_0::schema::{CommonSecurityAdvisoryFramework as Csaf, Vulnerability};
use index::ProductIndex;
use notes::NotesTab;
use overview::Overview;
use patternfly_yew::prelude::*;
use product_tree::ProductTreeTab;
use products::ProductsTab;
use std::{fmt, ops::Deref, rc::Rc};
use vulnerabilities::VulnerabilitiesTab;
use yew::prelude::*;

/// The CSAF specific tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsafTab {
    Overview,
    Notes,
    ProductTree,
    Products,
    Vulnerabilities,
}

impl CsafTab {
    pub const ALL: [Self; 5] = [
        Self::Overview,
        Self::Notes,
        Self::ProductTree,
        Self::Products,
        Self::Vulnerabilities,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Notes => "Notes",
            Self::ProductTree => "Product tree",
            Self::Products => "Products",
            Self::Vulnerabilities => "Vulnerabilities",
        }
    }
}

/// A parsed CSAF document, with its product index.
pub struct CsafDocument {
    pub csaf: Csaf,
    pub index: ProductIndex,
}

/// A shared [`CsafDocument`], compared by identity.
///
/// The document is parsed once, so comparing the pointer is enough for properties and memo
/// dependencies, and avoids comparing large documents on every render.
#[derive(Clone)]
pub struct Doc(Rc<CsafDocument>);

impl PartialEq for Doc {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl Deref for Doc {
    type Target = CsafDocument;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
enum ParseError {
    Json(serde_json::Error),
    MissingVersion,
    UnsupportedVersion(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(err) => write!(f, "invalid CSAF document: {err}"),
            Self::MissingVersion => write!(f, "the document has no 'document.csaf_version'"),
            Self::UnsupportedVersion(version) => {
                write!(f, "CSAF version {version} is not supported")
            }
        }
    }
}

/// Parse a CSAF document, checking the version first to report unsupported versions as such.
fn parse(text: &str) -> Result<Doc, ParseError> {
    let value = serde_json::from_str::<serde_json::Value>(text).map_err(ParseError::Json)?;

    match value
        .pointer("/document/csaf_version")
        .and_then(serde_json::Value::as_str)
    {
        Some("2.0") => {}
        Some(version) => return Err(ParseError::UnsupportedVersion(version.to_string())),
        None => return Err(ParseError::MissingVersion),
    }

    let csaf = serde_json::from_value::<Csaf>(value).map_err(ParseError::Json)?;
    let index = ProductIndex::new(&csaf);

    Ok(Doc(Rc::new(CsafDocument { csaf, index })))
}

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct CsafViewProps {
    pub document: Rc<String>,
    pub tab: CsafTab,
}

#[function_component(CsafView)]
pub fn csaf_view(props: &CsafViewProps) -> Html {
    let parsed = use_memo(props.document.clone(), |doc| parse(doc));

    match &*parsed {
        Err(err) => html! {
            <Alert title="Failed to read the CSAF document" r#type={AlertType::Danger} inline=true>
                <p>{ err.to_string() }</p>
            </Alert>
        },
        Ok(doc) => {
            let doc = doc.clone();
            match props.tab {
                CsafTab::Overview => html!(<Overview {doc} />),
                CsafTab::Notes => html!(<NotesTab {doc} />),
                CsafTab::ProductTree => html!(<ProductTreeTab {doc} />),
                CsafTab::Products => html!(<ProductsTab {doc} />),
                CsafTab::Vulnerabilities => html!(<VulnerabilitiesTab {doc} />),
            }
        }
    }
}

/// Render a product ID with the name of the product, if it is known.
fn product_ref(index: &ProductIndex, id: &str) -> Html {
    html! {
        <>
            <code>{ id }</code>
            if let Some(product) = index.get(id) {
                <br />
                <small>{ &product.name }</small>
            }
        </>
    }
}

/// The name of a vulnerability, e.g. its CVE.
fn vulnerability_name(n: usize, vuln: &Vulnerability) -> String {
    vuln.cve
        .as_deref()
        .cloned()
        .or_else(|| {
            vuln.ids
                .as_ref()
                .and_then(|ids| ids.first())
                .map(|id| format!("{}: {}", *id.system_name, *id.text))
        })
        .unwrap_or_else(|| format!("Vulnerability #{}", n + 1))
}

/// The placeholder for a missing value.
fn none() -> Html {
    html!(<i>{ "\u{2014}" }</i>)
}

#[cfg(test)]
mod test {
    use super::{ParseError, index::ProductOrigin, parse};
    use ::csaf::schema::csaf2_0::schema::RelationshipCategory;

    const DOCUMENT: &str = include_str!("../../../../etc/test-data/csaf/CVE-2024-5154.json");

    /// The interesting parts of an indexed product.
    fn product(
        doc: &super::Doc,
        id: &str,
    ) -> Option<(String, Option<String>, Option<String>, ProductOrigin)> {
        doc.index.get(id).map(|product| {
            (
                product.name.clone(),
                product.purl().map(str::to_string),
                product.cpe().map(str::to_string),
                product.origin.clone(),
            )
        })
    }

    #[test]
    fn index_products() {
        let doc = parse(DOCUMENT).expect("document parses");

        // 627 products in the branches, 621 from relationships
        assert_eq!(doc.index.products().len(), 1248);
        assert_eq!(
            product(&doc, "red_hat_openshift_container_platform_3.11"),
            Some((
                "Red Hat OpenShift Container Platform 3.11".to_string(),
                None,
                Some("cpe:/a:redhat:openshift:3.11".to_string()),
                ProductOrigin::Branch(vec![
                    "Red Hat".to_string(),
                    "Red Hat OpenShift Container Platform 3.11".to_string(),
                    "Red Hat OpenShift Container Platform 3.11".to_string(),
                ]),
            ))
        );
        assert_eq!(
            product(
                &doc,
                "8Base-RHOSE-4.12:bpftool-0:4.18.0-372.109.1.el8_6.aarch64"
            )
            .map(|(_, _, _, origin)| origin),
            Some(ProductOrigin::Relationship {
                category: RelationshipCategory::DefaultComponentOf,
                product_reference: "bpftool-0:4.18.0-372.109.1.el8_6.aarch64".to_string(),
                relates_to: "8Base-RHOSE-4.12".to_string(),
            })
        );
        assert_eq!(product(&doc, "unknown"), None);

        // a product of a relationship has no identifier of its own
        assert_eq!(
            [
                "8Base-RHOSE-4.12:bpftool-0:4.18.0-372.109.1.el8_6.aarch64",
                "red_hat_openshift_container_platform_3.11",
                "unknown",
            ]
            .map(|id| doc.index.identifiers(id)),
            [
                (
                    Some("pkg:rpm/redhat/bpftool@4.18.0-372.109.1.el8_6?arch=aarch64"),
                    Some("cpe:/a:redhat:openshift:4.12::el8"),
                ),
                (Some("cpe:/a:redhat:openshift:3.11"), None),
                (None, None),
            ]
        );
    }

    #[test]
    fn reject_unsupported_version() {
        let text = DOCUMENT.replacen(r#""csaf_version": "2.0""#, r#""csaf_version": "2.1""#, 1);
        assert!(matches!(
            parse(&text),
            Err(ParseError::UnsupportedVersion(version)) if version == "2.1"
        ));
    }
}
