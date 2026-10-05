use crate::{
    AppRoute, api,
    correlation::status_color,
    model::{SbomSummary, SbomVerdictCounts, VerdictStatus},
};
use patternfly_yew::prelude::*;
use std::collections::HashMap;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::prelude::*;
use yew_oauth2::prelude::*;

#[derive(Copy, Clone, Eq, PartialEq)]
enum Column {
    Name,
    DocumentId,
    Published,
    Packages,
    Verdicts,
}

/// An SBOM, with its verdict counts, once loaded.
#[derive(Clone, PartialEq)]
struct SbomEntry(SbomSummary, Option<SbomVerdictCounts>);

impl TableEntryRenderer<Column> for SbomEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!(&self.0.name).into(),
            Column::DocumentId => html!(self.0.document_id.as_deref().unwrap_or("-")).into(),
            Column::Published => html!(self.0.published.as_deref().unwrap_or("-")).into(),
            Column::Packages => html!(self.0.number_of_packages).into(),
            Column::Verdicts => verdict_counts(self.1.as_ref()).into(),
        }
    }
}

/// The ID of an SBOM, which the API returns in URN form (`urn:uuid:…`).
fn sbom_uuid(sbom: &SbomSummary) -> Option<Uuid> {
    Uuid::parse_str(&sbom.id).ok()
}

/// Labels for the non-zero verdict counts of an SBOM.
fn verdict_counts(counts: Option<&SbomVerdictCounts>) -> Html {
    let Some(counts) = counts else {
        return html!("…");
    };

    let labels = [
        (VerdictStatus::Affected, counts.affected),
        (VerdictStatus::Fixed, counts.fixed),
        (VerdictStatus::NotAffected, counts.not_affected),
        (
            VerdictStatus::UnderInvestigation,
            counts.under_investigation,
        ),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
    .map(|(status, count)| {
        html_nested! {
            <FlexItem>
                <Label
                    label={format!("{count} {}", status.label())}
                    color={status_color(status)}
                    compact=true
                />
            </FlexItem>
        }
    })
    .collect::<Vec<_>>();

    if labels.is_empty() {
        html!("-")
    } else {
        html! {
            <Flex space_items={[SpaceItems::Small]}>
                { for labels }
            </Flex>
        }
    }
}

#[function_component(SbomList)]
pub fn sbom_list() -> Html {
    let sboms = use_state(Vec::<SbomSummary>::new);
    // verdict counts by SBOM ID, `None` while loading
    let counts = use_state(|| Option::<HashMap<Uuid, SbomVerdictCounts>>::None);
    let loading = use_state(|| true);
    let error = use_state(|| Option::<String>::None);
    let search = use_state(String::new);
    let router = use_router::<AppRoute>();

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let sboms = sboms.clone();
        let counts = counts.clone();
        let loading = loading.clone();
        let error = error.clone();
        let search = search.clone();
        let token = token.clone();
        use_effect_with((*search).clone(), move |query| {
            let query = query.clone();
            spawn_local(async move {
                loading.set(true);
                error.set(None);
                counts.set(None);
                let items = match api::fetch_sboms(&query, 0, 50, token.as_deref()).await {
                    Ok(result) => result.items,
                    Err(e) => {
                        error.set(Some(e.to_string()));
                        Vec::new()
                    }
                };
                sboms.set(items.clone());
                loading.set(false);

                // the counts are secondary, the list is shown without them on failure
                let ids = items.iter().filter_map(sbom_uuid).collect();
                match api::count_verdicts(ids, token.as_deref()).await {
                    Ok(result) => {
                        counts.set(Some(result.into_iter().map(|c| (c.sbom_id, c)).collect()))
                    }
                    Err(e) => log::warn!("failed to load verdict counts: {e}"),
                }
            });
        });
    }

    let onsearch = {
        let search = search.clone();
        Callback::from(move |value: String| search.set(value))
    };

    let entries = use_memo(((*sboms).clone(), (*counts).clone()), |(items, counts)| {
        items
            .iter()
            .map(|s| {
                let counts = counts
                    .as_ref()
                    .zip(sbom_uuid(s))
                    .and_then(|(counts, id)| counts.get(&id))
                    .cloned();
                SbomEntry(s.clone(), counts)
            })
            .collect::<Vec<_>>()
    });

    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Name" index={Column::Name} />
            <TableColumn<Column> label="Document ID" index={Column::DocumentId} />
            <TableColumn<Column> label="Published" index={Column::Published} />
            <TableColumn<Column> label="Packages" index={Column::Packages} />
            <TableColumn<Column> label="Verdicts" index={Column::Verdicts} />
        </TableHeader<Column>>
    };

    let onrowclick = {
        Callback::from(move |entry: SbomEntry| {
            if let Some(router) = &router {
                router.push(AppRoute::Correlation { id: entry.0.id });
            }
        })
    };

    html! {
        <PageSection>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem>
                        <TextInput
                            placeholder="Search SBOMs..."
                            onchange={onsearch}
                            value={(*search).clone()}
                        />
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>

            if *loading {
                <Bullseye>
                    <Spinner />
                </Bullseye>
            } else if let Some(err) = &*error {
                <Alert title="Failed to load SBOMs" r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
            } else if sboms.is_empty() {
                <EmptyState
                    title="No SBOMs found"
                    icon={Icon::Search}
                    size={Size::XXXXLarge}
                >
                    { "Try adjusting your search or ingest some SBOMs first." }
                </EmptyState>
            } else {
                <Table<Column, UseTableData<Column, MemoizedTableModel<SbomEntry>>>
                    {header}
                    {entries}
                    {onrowclick}
                />
            }
        </PageSection>
    }
}
