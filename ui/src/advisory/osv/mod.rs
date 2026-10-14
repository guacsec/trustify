//! The OSV specific view of an advisory, parsed from its source document.
//!
//! OSV only states the affected versions of a package: the listed ones, and the intervals of its
//! ranges. A `fixed` event ends an interval, which is shown as a remediation, not as a status.
//! See <https://ossf.github.io/osv-schema/>.

mod affected;
mod overview;
mod references;

use super::none;
use ::osv::schema::Vulnerability;
use affected::AffectedTab;
use overview::Overview;
use patternfly_yew::prelude::*;
use references::ReferencesTab;
use serde::Serialize;
use serde_json::Value;
use std::{ops::Deref, rc::Rc};
use yew::prelude::*;

/// The OSV specific tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsvTab {
    Overview,
    Affected,
    References,
}

impl OsvTab {
    pub const ALL: [Self; 3] = [Self::Overview, Self::Affected, Self::References];

    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Affected => "Affected",
            Self::References => "References",
        }
    }
}

/// A parsed OSV record, compared by identity.
///
/// The record is parsed once, so comparing the pointer is enough for properties and memo
/// dependencies.
#[derive(Clone)]
pub struct Doc(Rc<Vulnerability>);

impl PartialEq for Doc {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl Deref for Doc {
    type Target = Vulnerability;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Parse an OSV record. Only JSON is supported, records in YAML are only shown as source.
fn parse(text: &str) -> Result<Doc, serde_json::Error> {
    serde_json::from_str(text).map(|osv| Doc(Rc::new(osv)))
}

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct OsvViewProps {
    pub document: Rc<String>,
    pub tab: OsvTab,
}

#[function_component(OsvView)]
pub fn osv_view(props: &OsvViewProps) -> Html {
    let parsed = use_memo(props.document.clone(), |doc| parse(doc));

    match &*parsed {
        Err(err) => html! {
            <Alert title="Failed to read the OSV record" r#type={AlertType::Danger} inline=true>
                <p>{ format!("Invalid OSV record: {err}") }</p>
                <p>{ "Only records in JSON are supported, see the Source tab for the document." }</p>
            </Alert>
        },
        Ok(doc) => {
            let doc = doc.clone();
            match props.tab {
                OsvTab::Overview => html!(<Overview {doc} />),
                OsvTab::Affected => html!(<AffectedTab {doc} />),
                OsvTab::References => html!(<ReferencesTab {doc} />),
            }
        }
    }
}

/// A value as the record states it, e.g. `ECOSYSTEM` for a range type, or `Debian:12` for an
/// ecosystem.
fn stated<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(value)) => value,
        Ok(value) => value.to_string(),
        Err(_) => "?".to_string(),
    }
}

/// A list of IDs, or the placeholder if there are none.
fn id_list(ids: Option<&Vec<String>>) -> Html {
    match ids {
        Some(ids) if !ids.is_empty() => html! {
            <Flex space_items={[SpaceItems::Small]}>
                { for ids.iter().map(|id| html_nested!(<FlexItem><code>{ id }</code></FlexItem>)) }
            </Flex>
        },
        _ => none(),
    }
}

/// Free-form JSON of the record (e.g. `database_specific`), collapsed.
fn json_section(title: &'static str, value: Option<&Value>) -> Html {
    let Some(value) = value else {
        return html!();
    };
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    html! {
        <ExpandableSection toggle_text_hidden={title} toggle_text_expanded={title}>
            <pre class="trustify-pre-wrap"><code>{ text }</code></pre>
        </ExpandableSection>
    }
}

#[cfg(test)]
mod test {
    use super::parse;

    const DOCUMENT: &str = include_str!(
        "../../../../etc/test-data/scenarios/S6_positive_baseline_osv_urllib3/osv/GHSA-g4mx-q9vg-27p4.json"
    );

    #[test]
    fn parse_record() {
        let doc = parse(DOCUMENT).expect("record parses");
        assert_eq!(
            (
                doc.id.as_str(),
                doc.aliases.as_deref(),
                doc.affected.as_ref().map(Vec::len),
            ),
            (
                "GHSA-g4mx-q9vg-27p4",
                Some(["CVE-2023-45803".to_string(), "PYSEC-2023-212".to_string()].as_slice()),
                Some(2),
            )
        );
    }

    #[test]
    fn reject_yaml() {
        assert!(parse("id: GHSA-g4mx-q9vg-27p4\nmodified: 2026-02-04T03:30:16Z\n").is_err());
    }
}
