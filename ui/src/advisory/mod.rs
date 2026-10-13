//! The advisory explorer: information from the database, and a format specific view of the
//! advisory's source document.

mod common;
mod csaf;
mod cve;
mod osv;
mod source;
mod statements;

use self::{
    cve::{CveTab, CveView},
    osv::{OsvTab, OsvView},
};
use crate::{AppRoute, api};
use common::CommonTab;
use csaf::{CsafTab, CsafView};
use patternfly_yew::prelude::*;
use source::SourceTab;
use std::rc::Rc;
use trustify_client::api::types::{AdvisoryDetails, Labels};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

/// The format of an advisory's source document, from the `type` label the ingestor sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvisoryFormat {
    Csaf,
    Cve,
    Osv,
    Nvd,
    Other(String),
    Unknown,
}

impl AdvisoryFormat {
    fn from_details(details: &AdvisoryDetails) -> Self {
        Self::from_labels(&details.labels)
    }

    /// The format, from the labels of an advisory.
    pub fn from_labels(labels: &Labels) -> Self {
        match labels.0.get("type").map(String::as_str) {
            Some("csaf") => Self::Csaf,
            Some("cve") => Self::Cve,
            Some("osv") => Self::Osv,
            Some("nvd") => Self::Nvd,
            Some(other) => Self::Other(other.to_string()),
            None => Self::Unknown,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Csaf => "CSAF".into(),
            Self::Cve => "CVE".into(),
            Self::Osv => "OSV".into(),
            Self::Nvd => "NVD".into(),
            Self::Other(other) => other.clone(),
            Self::Unknown => "Unknown format".into(),
        }
    }

    /// The tabs to show: the format specific ones first, then the common ones.
    fn tabs(&self) -> Vec<AdvisoryTab> {
        let mut tabs = match self {
            Self::Csaf => CsafTab::ALL.into_iter().map(AdvisoryTab::Csaf).collect(),
            Self::Cve => CveTab::ALL.into_iter().map(AdvisoryTab::Cve).collect(),
            Self::Osv => OsvTab::ALL.into_iter().map(AdvisoryTab::Osv).collect(),
            _ => Vec::new(),
        };
        tabs.extend([AdvisoryTab::Common, AdvisoryTab::Source]);
        tabs
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdvisoryTab {
    Csaf(CsafTab),
    Cve(CveTab),
    Osv(OsvTab),
    Common,
    Source,
}

impl AdvisoryTab {
    fn title(self) -> &'static str {
        match self {
            Self::Csaf(tab) => tab.title(),
            Self::Cve(tab) => tab.title(),
            Self::Osv(tab) => tab.title(),
            Self::Common => "Common",
            Self::Source => "Source",
        }
    }
}

/// The state of a request.
enum Fetch<T> {
    Loading,
    Ready(T),
    Failed(String),
}

impl<T> Fetch<T> {
    /// Render the fetched value, or the state of the request.
    fn render(&self, error_title: &'static str, f: impl FnOnce(&T) -> Html) -> Html {
        match self {
            Self::Loading => html! {
                <Bullseye>
                    <Spinner />
                </Bullseye>
            },
            Self::Failed(err) => html! {
                <Alert title={error_title} r#type={AlertType::Danger} inline=true>
                    <p>{ err }</p>
                </Alert>
            },
            Self::Ready(value) => f(value),
        }
    }
}

/// The placeholder for a missing value.
fn none() -> Html {
    html!(<i>{ "\u{2014}" }</i>)
}

/// A card of fields, each a [`DescriptionGroup`], with the term next to the value.
fn field_card(title: &'static str, fields: Html) -> Html {
    html! {
        <Card size={CardSize::Compact} full_height=true>
            <CardTitle>{ title }</CardTitle>
            <CardBody>
                <DescriptionList mode={[DescriptionListMode::Horizontal.all()]} compact=true>
                    { fields }
                </DescriptionList>
            </CardBody>
        </Card>
    }
}

/// Cards next to each other: one per row on small screens, up to three on wide ones.
fn card_grid(cards: impl IntoIterator<Item = Html>) -> Html {
    html! {
        <Grid gutter=true>
            { for cards.into_iter().map(|card| html_nested! {
                <GridItem cols={[12.all(), 6.md(), 4.xl()]}>{ card }</GridItem>
            }) }
        </Grid>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct AdvisoryPageProps {
    pub advisory_id: String,
}

#[function_component(AdvisoryPage)]
pub fn advisory_page(props: &AdvisoryPageProps) -> Html {
    let details = use_state(|| Fetch::<Rc<AdvisoryDetails>>::Loading);
    let document = use_state(|| Fetch::<Rc<String>>::Loading);
    let selected = use_state_eq(|| Option::<AdvisoryTab>::None);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let details = details.clone();
        let document = document.clone();
        let selected = selected.clone();
        use_effect_with(props.advisory_id.clone(), move |id| {
            details.set(Fetch::Loading);
            document.set(Fetch::Loading);
            selected.set(None);

            // Independent requests: the database information is still useful without the
            // source document, and the other way round.
            {
                let id = id.clone();
                let token = token.clone();
                spawn_local(async move {
                    details.set(match api::fetch_advisory(&id, token.as_deref()).await {
                        Ok(data) => Fetch::Ready(Rc::new(data)),
                        Err(e) => Fetch::Failed(e.to_string()),
                    });
                });
            }
            let id = id.clone();
            spawn_local(async move {
                document.set(
                    match api::fetch_advisory_document(&id, token.as_deref()).await {
                        Ok(data) => Fetch::Ready(Rc::new(data)),
                        Err(e) => Fetch::Failed(e.to_string()),
                    },
                );
            });
        });
    }

    let format = match &*details {
        Fetch::Ready(details) => Some(AdvisoryFormat::from_details(details)),
        _ => None,
    };
    let tabs = format.as_ref().unwrap_or(&AdvisoryFormat::Unknown).tabs();
    let current = (*selected)
        .filter(|tab| tabs.contains(tab))
        .or_else(|| tabs.first().copied())
        .unwrap_or(AdvisoryTab::Common);

    let onselect = {
        let selected = selected.clone();
        Callback::from(move |tab| selected.set(Some(tab)))
    };

    let identifier = match &*details {
        Fetch::Ready(details) => Some(details.identifier.clone()),
        _ => None,
    };

    // The tab content is rendered outside of the (detached) tabs, so only the selected tab is
    // rendered. Product lists of large CSAF documents are expensive to render.
    let content = match current {
        AdvisoryTab::Common => details.render(
            "Failed to load advisory",
            |details| html!(<CommonTab advisory_id={props.advisory_id.clone()} details={details.clone()} />),
        ),
        AdvisoryTab::Source => document.render("Failed to load source document", |doc| {
            let file_name = format!(
                "{}.json",
                identifier
                    .as_deref()
                    .unwrap_or(&props.advisory_id)
                    .replace('/', "_")
            );
            html!(<SourceTab document={doc.clone()} {file_name} />)
        }),
        AdvisoryTab::Csaf(tab) => document.render(
            "Failed to load source document",
            |doc| html!(<CsafView document={doc.clone()} {tab} />),
        ),
        AdvisoryTab::Cve(tab) => document.render(
            "Failed to load source document",
            |doc| html!(<CveView document={doc.clone()} {tab} />),
        ),
        AdvisoryTab::Osv(tab) => document.render(
            "Failed to load source document",
            |doc| html!(<OsvView document={doc.clone()} {tab} />),
        ),
    };

    html! {
        <PageSection>
            <Breadcrumb>
                <BreadcrumbRouterItem<AppRoute> to={AppRoute::AdvisoryList}>
                    { "Advisories" }
                </BreadcrumbRouterItem<AppRoute>>
                <BreadcrumbItem>
                    { format!("Advisory: {}", identifier.as_deref().unwrap_or_default()) }
                </BreadcrumbItem>
            </Breadcrumb>

            <br />

            if let Fetch::Ready(details) = &*details {
                <Flex space_items={[SpaceItems::Small]} modifiers={[FlexModifier::Align(Alignment::Center)]}>
                    <FlexItem>
                        <Title level={Level::H1}>{ &details.identifier }</Title>
                    </FlexItem>
                    { for format.as_ref().map(|format| html_nested! {
                        <FlexItem>
                            <Label label={format.label()} color={Color::Blue} />
                        </FlexItem>
                    }) }
                    { for details.withdrawn.is_some().then(|| html_nested! {
                        <FlexItem>
                            <Label label="Withdrawn" color={Color::Red} />
                        </FlexItem>
                    }) }
                </Flex>
                if let Some(title) = &details.title {
                    <p>{ title }</p>
                }
            }

            <Tabs<AdvisoryTab> detached=true selected={current} {onselect}>
                { for tabs.into_iter().map(|tab| html_nested! {
                    <Tab<AdvisoryTab> index={tab} title={tab.title()} />
                }) }
            </Tabs<AdvisoryTab>>

            <div class="pf-v6-u-pt-md">
                { content }
            </div>
        </PageSection>
    }
}
