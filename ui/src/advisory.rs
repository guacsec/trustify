use crate::{AppRoute, api};
use patternfly_yew::prelude::*;
use trustify_client::api::types::{AdvisoryDetails, AdvisoryVulnerabilitySummary, Severity};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct AdvisoryPageProps {
    pub advisory_id: String,
}

#[function_component(AdvisoryPage)]
pub fn advisory_page(props: &AdvisoryPageProps) -> Html {
    let result = use_state(|| Option::<AdvisoryDetails>::None);
    let loading = use_state(|| true);
    let error = use_state(|| Option::<String>::None);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let advisory_id = props.advisory_id.clone();
        let result = result.clone();
        let loading = loading.clone();
        let error = error.clone();
        let token = token.clone();
        use_effect_with(advisory_id.clone(), move |id| {
            let id = id.clone();
            spawn_local(async move {
                loading.set(true);
                error.set(None);
                match api::fetch_advisory(&id, token.as_deref()).await {
                    Ok(data) => result.set(Some(data)),
                    Err(e) => error.set(Some(e.to_string())),
                }
                loading.set(false);
            });
        });
    }

    html! {
        <PageSection>
            <Breadcrumb>
                <BreadcrumbRouterItem<AppRoute> to={AppRoute::SbomList}>
                    { "SBOMs" }
                </BreadcrumbRouterItem<AppRoute>>
                <BreadcrumbItem>
                    if let Some(data) = &*result {
                        { format!("Advisory: {}", data.identifier) }
                    } else {
                        { "Advisory" }
                    }
                </BreadcrumbItem>
            </Breadcrumb>

            if *loading {
                <Bullseye>
                    <Spinner />
                </Bullseye>
            } else if let Some(err) = &*error {
                <Alert title="Failed to load advisory" r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
            } else if let Some(data) = &*result {
                <AdvisoryContent details={data.clone()} />
            }
        </PageSection>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct AdvisoryContentProps {
    details: AdvisoryDetails,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum VulnColumn {
    Identifier,
    Title,
    Severity,
    Score,
}

#[derive(Clone, PartialEq)]
struct VulnEntry(AdvisoryVulnerabilitySummary);

impl TableEntryRenderer<VulnColumn> for VulnEntry {
    fn render_cell(&self, context: CellContext<'_, VulnColumn>) -> Cell {
        match context.column {
            VulnColumn::Identifier => html!(<strong>{ &self.0.identifier }</strong>).into(),
            VulnColumn::Title => html!(self.0.title.as_deref().unwrap_or("\u{2014}")).into(),
            VulnColumn::Severity => {
                if let Some(bs) = &self.0.base_score {
                    html!(severity_label(&bs.severity)).into()
                } else {
                    html!(<i>{ "\u{2014}" }</i>).into()
                }
            }
            VulnColumn::Score => {
                if let Some(bs) = &self.0.base_score {
                    html!(format!("{:.1}", bs.score)).into()
                } else {
                    html!(<i>{ "\u{2014}" }</i>).into()
                }
            }
        }
    }
}

#[function_component(AdvisoryContent)]
fn advisory_content(props: &AdvisoryContentProps) -> Html {
    let details = &props.details;

    let entries = use_memo(details.vulnerabilities.clone(), |vulns| {
        vulns
            .iter()
            .map(|v| VulnEntry(v.clone()))
            .collect::<Vec<_>>()
    });

    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<VulnColumn>>
            <TableColumn<VulnColumn> label="Vulnerability" index={VulnColumn::Identifier} />
            <TableColumn<VulnColumn> label="Title" index={VulnColumn::Title} />
            <TableColumn<VulnColumn> label="Severity" index={VulnColumn::Severity} />
            <TableColumn<VulnColumn> label="Score" index={VulnColumn::Score} />
        </TableHeader<VulnColumn>>
    };

    html! {
        <>
            <Title level={Level::H1}>
                { &details.identifier }
            </Title>
            if let Some(title) = &details.title {
                <p>{ title }</p>
            }

            <br />

            <DescriptionList>
                if let Some(issuer) = &details.issuer {
                    <DescriptionGroup term="Issuer">
                        { &issuer.name }
                    </DescriptionGroup>
                }
                if let Some(published) = &details.published {
                    <DescriptionGroup term="Published">
                        { published.to_string() }
                    </DescriptionGroup>
                }
                if let Some(modified) = &details.modified {
                    <DescriptionGroup term="Modified">
                        { modified.to_string() }
                    </DescriptionGroup>
                }
            </DescriptionList>

            <br />

            if !details.vulnerabilities.is_empty() {
                <Title level={Level::H2}>
                    { "Vulnerabilities " }
                    <Badge>{ details.vulnerabilities.len().to_string() }</Badge>
                </Title>
                <Table<VulnColumn, UseTableData<VulnColumn, MemoizedTableModel<VulnEntry>>>
                    mode={TableMode::Compact}
                    {header}
                    {entries}
                />
            } else {
                <EmptyState
                    title="No vulnerabilities"
                    icon={Icon::CheckCircle}
                    size={Size::XXXXLarge}
                >
                    { "This advisory does not reference any vulnerabilities." }
                </EmptyState>
            }
        </>
    }
}

fn severity_label(severity: &Severity) -> Html {
    let (label, color) = match severity {
        Severity::Critical => ("Critical", Color::Red),
        Severity::High => ("High", Color::Orange),
        Severity::Medium => ("Medium", Color::Yellow),
        Severity::Low => ("Low", Color::Blue),
        Severity::None => ("None", Color::Grey),
    };
    html! { <Label label={label} {color} /> }
}
