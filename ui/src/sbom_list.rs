use crate::{AppRoute, api, model::SbomSummary};
use patternfly_yew::prelude::*;
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
}

#[derive(Clone, PartialEq)]
struct SbomEntry(SbomSummary);

impl TableEntryRenderer<Column> for SbomEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!(&self.0.name).into(),
            Column::DocumentId => html!(self.0.document_id.as_deref().unwrap_or("-")).into(),
            Column::Published => html!(self.0.published.as_deref().unwrap_or("-")).into(),
            Column::Packages => html!(self.0.number_of_packages).into(),
        }
    }
}

#[function_component(SbomList)]
pub fn sbom_list() -> Html {
    let sboms = use_state(Vec::<SbomSummary>::new);
    let loading = use_state(|| true);
    let error = use_state(|| Option::<String>::None);
    let search = use_state(String::new);
    let router = use_router::<AppRoute>();

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let sboms = sboms.clone();
        let loading = loading.clone();
        let error = error.clone();
        let search = search.clone();
        let token = token.clone();
        use_effect_with((*search).clone(), move |query| {
            let query = query.clone();
            spawn_local(async move {
                loading.set(true);
                error.set(None);
                match api::fetch_sboms(&query, 0, 50, token.as_deref()).await {
                    Ok(result) => sboms.set(result.items),
                    Err(e) => error.set(Some(e.to_string())),
                }
                loading.set(false);
            });
        });
    }

    let onsearch = {
        let search = search.clone();
        Callback::from(move |value: String| search.set(value))
    };

    let entries = use_memo((*sboms).clone(), |items| {
        items
            .iter()
            .map(|s| SbomEntry(s.clone()))
            .collect::<Vec<_>>()
    });

    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Name" index={Column::Name} />
            <TableColumn<Column> label="Document ID" index={Column::DocumentId} />
            <TableColumn<Column> label="Published" index={Column::Published} />
            <TableColumn<Column> label="Packages" index={Column::Packages} />
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
