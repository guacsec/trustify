//! Importers: their state, their runs, and their configuration.

use crate::{
    AppRoute, api,
    confirm::ConfirmDialog,
    correlation::timestamp,
    model::{Importer, ImporterReport, ImporterState, PaginatedResults},
    monaco::ensure_environment,
    stored::use_stored_pagination,
};
use ::monaco::{
    api::TextModel, sys::editor::IStandaloneEditorConstructionOptions, yew::CodeEditor,
};
use patternfly_yew::prelude::*;
use serde_json::Value;
use std::{future::Future, pin::Pin};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::{components::Link, prelude::use_router};
use yew_oauth2::prelude::use_latest_access_token;

/// A change of an importer, resolving to an error message on failure.
type Change = Pin<Box<dyn Future<Output = Result<(), String>>>>;

/// The configuration a new importer starts with.
const TEMPLATE: &str = r#"{
  "sbom": {
    "source": "https://example.com/sboms/",
    "period": "1d",
    "disabled": true
  }
}"#;

/// Reload the page data every few seconds while the page is visible, by bumping `generation`.
#[hook]
fn use_polling(generation: UseStateHandle<u64>) {
    use_effect_with((), move |_| {
        let timer = gloo_timers::callback::Interval::new(5000, move || {
            if !gloo_utils::document().hidden() {
                generation.set(js_sys::Date::now() as u64);
            }
        });
        move || drop(timer)
    });
}

/// Run a change of an importer in the background, reporting its outcome.
fn run(change: Change, on_done: Callback<Result<(), String>>) {
    spawn_local(async move { on_done.emit(change.await) });
}

fn state_cell(importer: &Importer) -> Html {
    if importer.disabled() {
        return html! { <Label label="Disabled" color={Color::Grey} compact=true /> };
    }
    match importer.state {
        ImporterState::Waiting => {
            html! { <Label label="Waiting" color={Color::Blue} compact=true /> }
        }
        ImporterState::Running => {
            let progress = &importer.progress;
            let description = progress.message.clone().unwrap_or("Running".into());
            match (progress.percent, progress.current, progress.total) {
                (Some(value), Some(current), Some(total)) => html! {
                    <Progress
                        {value}
                        {description}
                        value_text={format!("{current} of {total}")}
                        size={ProgressSize::Small}
                    />
                },
                _ => html! { <Label label={description} color={Color::Green} compact=true /> },
            }
        }
    }
}

fn optional_timestamp(value: Option<&time::OffsetDateTime>) -> Html {
    value.map(timestamp).unwrap_or_else(|| html!("-"))
}

#[derive(Clone, PartialEq, Properties)]
struct ActionsProps {
    importer: Importer,
    /// Called with the outcome of a change.
    on_done: Callback<Result<(), String>>,
    /// Called after the importer was deleted.
    on_deleted: Callback<()>,
    /// Show the menu as a kebab, for table rows, instead of an "Actions" toggle.
    #[prop_or_default]
    kebab: bool,
}

/// A menu to enable, run, and delete an importer.
#[function_component(ImporterActions)]
fn importer_actions(props: &ActionsProps) -> Html {
    #[allow(clippy::expect_used)]
    let backdrop = use_backdrop().expect("ImporterActions requires BackdropViewer");
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());
    let name = props.importer.name.clone();

    let enabled = !props.importer.disabled();
    let on_enabled = {
        let (name, token, on_done) = (name.clone(), token.clone(), props.on_done.clone());
        Callback::from(move |()| {
            let enabled = !enabled;
            let (name, token) = (name.clone(), token.clone());
            run(
                Box::pin(async move {
                    api::set_importer_enabled(&name, enabled, token.as_deref())
                        .await
                        .map_err(|e| format!("Failed to change importer {name}: {e}"))
                }),
                on_done.clone(),
            );
        })
    };

    let on_run = {
        let (name, token, on_done) = (name.clone(), token.clone(), props.on_done.clone());
        Callback::from(move |()| {
            let (name, token) = (name.clone(), token.clone());
            run(
                Box::pin(async move {
                    api::force_importer(&name, token.as_deref())
                        .await
                        .map_err(|e| format!("Failed to run importer {name}: {e}"))
                }),
                on_done.clone(),
            );
        })
    };

    let on_delete = {
        let (on_done, on_deleted) = (props.on_done.clone(), props.on_deleted.clone());
        let deleted = name.clone();
        let on_confirm = Callback::from(move |()| {
            let (name, token, on_done, on_deleted) = (
                deleted.clone(),
                token.clone(),
                on_done.clone(),
                on_deleted.clone(),
            );
            spawn_local(async move {
                match api::delete_importer(&name, token.as_deref()).await {
                    Ok(()) => on_deleted.emit(()),
                    Err(e) => on_done.emit(Err(format!("Failed to delete importer {name}: {e}"))),
                }
            });
        });
        Callback::from(move |()| {
            backdrop.open(Backdrop::new(html! {
                <Bullseye>
                    <ConfirmDialog title="Delete importer?" confirm="Delete" danger=true on_confirm={on_confirm.clone()}>
                        <p>
                            { "The importer " }<strong>{ &name }</strong>
                            { " and its reports will be deleted. Documents it already ingested are kept." }
                        </p>
                    </ConfirmDialog>
                </Bullseye>
            }));
        })
    };

    let (variant, icon, text) = match props.kebab {
        true => (MenuToggleVariant::Plain, Some(html!(Icon::EllipsisV)), None),
        false => (MenuToggleVariant::Default, None, Some(html!("Actions"))),
    };

    html! {
        <Dropdown {variant} {icon} {text} aria_label="Actions" position={Position::Right}>
            <MenuAction onclick={on_enabled}>{ if enabled { "Disable" } else { "Enable" } }</MenuAction>
            <MenuAction
                onclick={on_run}
                disabled={!enabled || props.importer.state == ImporterState::Running}
            >
                { "Run now" }
            </MenuAction>
            <ListDivider />
            <MenuAction onclick={on_delete} danger=true>{ "Delete" }</MenuAction>
        </Dropdown>
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Column {
    Name,
    Kind,
    Source,
    Period,
    State,
    LastRun,
    LastSuccess,
    Actions,
}

#[function_component(ImporterListPage)]
pub fn importer_list_page() -> Html {
    #[allow(clippy::expect_used)]
    let backdrop = use_backdrop().expect("ImporterListPage requires BackdropViewer");
    let importers = use_state(|| None::<Vec<Importer>>);
    let error = use_state(|| None::<String>);
    let generation = use_state(|| 0u64);
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());

    use_polling(generation.clone());

    {
        let (importers, error) = (importers.clone(), error.clone());
        use_effect_with((*generation, token.clone()), move |(_, token)| {
            let token = token.clone();
            spawn_local(async move {
                match api::fetch_importers(token.as_deref()).await {
                    Ok(mut result) => {
                        result.sort_by(|a, b| a.name.cmp(&b.name));
                        importers.set(Some(result));
                    }
                    Err(e) => error.set(Some(format!("Failed to load the importers: {e}"))),
                }
            });
        });
    }

    let reload = {
        let generation = generation.clone();
        Callback::from(move |()| generation.set(js_sys::Date::now() as u64))
    };

    let on_done = {
        let (error, reload) = (error.clone(), reload.clone());
        Callback::from(move |result: Result<(), String>| {
            error.set(result.err());
            reload.emit(());
        })
    };

    let on_add = {
        let reload = reload.clone();
        Callback::from(move |_: MouseEvent| {
            backdrop.open(Backdrop::new(html! {
                <Bullseye><CreateImporter on_saved={reload.clone()} /></Bullseye>
            }));
        })
    };

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Name" index={Column::Name} />
            <TableColumn<Column> label="Type" index={Column::Kind} />
            <TableColumn<Column> label="Source" index={Column::Source} />
            <TableColumn<Column> label="Period" index={Column::Period} />
            <TableColumn<Column> label="State" index={Column::State} />
            <TableColumn<Column> label="Last run" index={Column::LastRun} />
            <TableColumn<Column> label="Last success" index={Column::LastSuccess} />
            <TableColumn<Column> label="" index={Column::Actions} />
        </TableHeader<Column>>
    };

    html! {
        <PageSection><Stack gutter=true>
            <Title level={Level::H1}>{ "Importers" }</Title>
            <p>{ "Importers periodically fetch documents from a source and ingest them." }</p>
            if let Some(err) = &*error {
                <Alert title="Error" r#type={AlertType::Danger} inline=true><p>{ err }</p></Alert>
            }
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem>
                        <Button variant={ButtonVariant::Primary} onclick={on_add}>{ "Add importer" }</Button>
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>
            if let Some(importers) = &*importers {
                if importers.is_empty() {
                    <EmptyState title="No importers" icon={Icon::Cubes} size={Size::Large}>
                        { "Documents are only ingested when uploaded. Add an importer to fetch them from a source." }
                    </EmptyState>
                } else {
                    <ComposableTable mode={TableMode::Compact}>
                        { header }
                        <TableBody>
                            { for importers.iter().map(|importer| html! {
                                <TableRow key={importer.name.clone()}>
                                    <TableData data_label="Name">
                                        <Link<AppRoute> to={AppRoute::Importer { name: importer.name.clone() }}>{ &importer.name }</Link<AppRoute>>
                                    </TableData>
                                    <TableData data_label="Type">{ importer.kind() }</TableData>
                                    <TableData data_label="Source"><span class="trustify-break-all">{ importer.text("source") }</span></TableData>
                                    <TableData data_label="Period">{ importer.text("period") }</TableData>
                                    <TableData data_label="State">{ state_cell(importer) }</TableData>
                                    <TableData data_label="Last run">
                                        { optional_timestamp(importer.last_run.as_ref()) }
                                        if importer.last_error.is_some() {
                                            { " " }<Label label="Failed" color={Color::Red} compact=true />
                                        }
                                    </TableData>
                                    <TableData data_label="Last success">{ optional_timestamp(importer.last_success.as_ref()) }</TableData>
                                    <TableData action=true>
                                        <ImporterActions importer={importer.clone()} on_done={on_done.clone()} on_deleted={reload.clone()} kebab=true />
                                    </TableData>
                                </TableRow>
                            }) }
                        </TableBody>
                    </ComposableTable>
                }
            } else if error.is_none() {
                <Bullseye><Spinner /></Bullseye>
            }
        </Stack></PageSection>
    }
}

/// Editor options for an editable JSON text.
fn editor_options() -> IStandaloneEditorConstructionOptions {
    let options = IStandaloneEditorConstructionOptions::default();
    options.set_language(Some("json"));
    options.set_theme(Some("vs"));
    options.set_automatic_layout(Some(true));
    options.set_scroll_beyond_last_line(Some(false));
    options
}

/// A JSON editor model, disposed with the component.
#[hook]
fn use_json_model(text: &str) -> Option<TextModel> {
    let model = use_memo((), {
        let text = text.to_string();
        move |()| {
            TextModel::create(&text, Some("json"), None)
                .inspect_err(|err| log::error!("Failed to create the editor model: {err:?}"))
                .ok()
        }
    });
    use_effect_with(model.clone(), |model| {
        let model = model.clone();
        move || {
            if let Some(model) = &*model {
                model.as_ref().dispose();
            }
        }
    });
    (*model).clone()
}

#[derive(Clone, PartialEq, Properties)]
struct JsonEditorProps {
    model: Option<TextModel>,
}

#[function_component(JsonEditor)]
fn json_editor(props: &JsonEditorProps) -> Html {
    ensure_environment();
    // Changing the options re-creates the editor, so they are created once.
    let options = use_memo((), |()| editor_options());
    html! {
        <CodeEditor classes="trustify-config-editor" options={(*options).clone()} model={props.model.clone()} />
    }
}

/// Parse the text of an editor as JSON.
fn parse_config(model: Option<&TextModel>) -> Result<Value, String> {
    let text = model.map(TextModel::get_value).unwrap_or_default();
    serde_json::from_str(&text).map_err(|e| format!("Invalid JSON: {e}"))
}

#[derive(Clone, PartialEq, Properties)]
struct CreateImporterProps {
    on_saved: Callback<()>,
}

/// A modal creating an importer.
#[function_component(CreateImporter)]
fn create_importer(props: &CreateImporterProps) -> Html {
    #[allow(clippy::expect_used)]
    let backdrop = use_backdrop().expect("CreateImporter requires BackdropViewer");
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());
    let name = use_state(String::new);
    let error = use_state(|| None::<String>);
    let saving = use_state(|| false);
    let model = use_json_model(TEMPLATE);

    let save = {
        let (name, error, saving, model) =
            (name.clone(), error.clone(), saving.clone(), model.clone());
        let (backdrop, on_saved) = (backdrop.clone(), props.on_saved.clone());
        Callback::from(move |_: MouseEvent| {
            let name = name.trim().to_string();
            if *saving || name.is_empty() {
                return;
            }
            let config = match parse_config(model.as_ref()) {
                Ok(config) => config,
                Err(e) => return error.set(Some(e)),
            };
            let (token, error, saving, backdrop, on_saved) = (
                token.clone(),
                error.clone(),
                saving.clone(),
                backdrop.clone(),
                on_saved.clone(),
            );
            saving.set(true);
            spawn_local(async move {
                match api::create_importer(&name, &config, token.as_deref()).await {
                    Ok(()) => {
                        backdrop.close();
                        on_saved.emit(());
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
                saving.set(false);
            });
        })
    };

    let close = Callback::from(move |_: MouseEvent| backdrop.close());
    let footer = html! {
        <>
            <Button variant={ButtonVariant::Primary} onclick={save} disabled={*saving || name.trim().is_empty()}>{ "Add" }</Button>
            <Button variant={ButtonVariant::Link} onclick={close} disabled={*saving}>{ "Cancel" }</Button>
        </>
    };

    html! {
        <Modal title="Add importer" variant={ModalVariant::Large} {footer}>
            <Form onsubmit={Callback::from(|e: SubmitEvent| e.prevent_default())}>
                if let Some(err) = &*error {
                    <Alert title="Unable to save" r#type={AlertType::Danger} inline=true><p>{ err }</p></Alert>
                }
                <FormGroup label="Name" required=true>
                    <TextInput value={(*name).clone()} onchange={{ let name = name.clone(); Callback::from(move |v: String| name.set(v)) }} />
                </FormGroup>
                <FormGroup label="Configuration (JSON)" required=true>
                    <JsonEditor {model} />
                </FormGroup>
            </Form>
        </Modal>
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ImporterTab {
    Reports,
    Configuration,
}

#[derive(Clone, PartialEq, Properties)]
pub struct ImporterPageProps {
    pub name: String,
}

#[function_component(ImporterPage)]
pub fn importer_page(props: &ImporterPageProps) -> Html {
    let importer = use_state(|| None::<Importer>);
    let error = use_state(|| None::<String>);
    let generation = use_state(|| 0u64);
    let tab = use_state_eq(|| ImporterTab::Reports);
    let router = use_router::<AppRoute>();
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());

    use_polling(generation.clone());

    {
        let (importer, error) = (importer.clone(), error.clone());
        use_effect_with(
            (props.name.clone(), *generation, token.clone()),
            move |(name, _, token)| {
                let (name, token) = (name.clone(), token.clone());
                spawn_local(async move {
                    match api::fetch_importer(&name, token.as_deref()).await {
                        Ok((result, _)) => importer.set(Some(result)),
                        Err(e) => error.set(Some(format!("Failed to load the importer: {e}"))),
                    }
                });
            },
        );
    }

    let on_done = {
        let (error, generation) = (error.clone(), generation.clone());
        Callback::from(move |result: Result<(), String>| {
            error.set(result.err());
            generation.set(js_sys::Date::now() as u64);
        })
    };
    let on_deleted = Callback::from(move |()| {
        if let Some(router) = &router {
            router.push(AppRoute::Importers);
        }
    });
    let onselect = {
        let tab = tab.clone();
        Callback::from(move |value| tab.set(value))
    };

    html! {
        <PageSection><Stack gutter=true>
            <Content>
                <Link<AppRoute> to={AppRoute::Importers}>{ "Importers" }</Link<AppRoute>>
            </Content>
            <Flex modifiers={[FlexModifier::Align(Alignment::Center)]}>
                <FlexItem><Title level={Level::H1}>{ &props.name }</Title></FlexItem>
                { for importer.as_ref().map(|importer| html_nested! {
                    <FlexItem modifiers={[FlexModifier::Align(Alignment::Right)]}>
                        <ImporterActions importer={importer.clone()} {on_done} {on_deleted} />
                    </FlexItem>
                }) }
            </Flex>
            if let Some(err) = &*error {
                <Alert title="Error" r#type={AlertType::Danger} inline=true><p>{ err }</p></Alert>
            }
            if let Some(importer) = &*importer {
                <DescriptionList>
                    <DescriptionGroup term="Type">{ importer.kind() }</DescriptionGroup>
                    <DescriptionGroup term="Description">{ importer.text("description") }</DescriptionGroup>
                    <DescriptionGroup term="State">{ state_cell(importer) }</DescriptionGroup>
                    <DescriptionGroup term="Last run">{ optional_timestamp(importer.last_run.as_ref()) }</DescriptionGroup>
                    <DescriptionGroup term="Last success">{ optional_timestamp(importer.last_success.as_ref()) }</DescriptionGroup>
                    if let Some(err) = &importer.last_error {
                        <DescriptionGroup term="Last error">{ err }</DescriptionGroup>
                    }
                </DescriptionList>
                <Tabs<ImporterTab> detached=true selected={*tab} {onselect}>
                    <Tab<ImporterTab> index={ImporterTab::Reports} title="Reports" />
                    <Tab<ImporterTab> index={ImporterTab::Configuration} title="Configuration" />
                </Tabs<ImporterTab>>
                <div>
                    { match *tab {
                        ImporterTab::Reports => html! { <Reports name={props.name.clone()} generation={*generation} /> },
                        ImporterTab::Configuration => html! { <Configuration name={props.name.clone()} /> },
                    } }
                </div>
            } else if error.is_none() {
                <Bullseye><Spinner /></Bullseye>
            }
        </Stack></PageSection>
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ReportColumn {
    Created,
    Items,
    Error,
}

#[derive(Clone, PartialEq, Properties)]
struct ReportsProps {
    name: String,
    /// Reloads the reports when it changes.
    generation: u64,
}

/// The messages of a report, as `phase / file: severity: message` lines.
fn report_messages(report: &ImporterReport) -> Vec<String> {
    let Some(phases) = report
        .report
        .as_ref()
        .and_then(|r| r.get("messages"))
        .and_then(Value::as_object)
    else {
        return vec![];
    };
    phases
        .iter()
        .filter_map(|(phase, files)| Some((phase, files.as_object()?)))
        .flat_map(|(phase, files)| {
            files.iter().flat_map(move |(file, messages)| {
                messages.as_array().into_iter().flatten().map(move |m| {
                    format!(
                        "{phase} / {file}: {}: {}",
                        m.get("severity")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                        m.get("message").and_then(Value::as_str).unwrap_or_default(),
                    )
                })
            })
        })
        .collect()
}

#[function_component(Reports)]
fn reports(props: &ReportsProps) -> Html {
    let reports = use_state(|| None::<PaginatedResults<ImporterReport>>);
    let error = use_state(|| None::<String>);
    let total = reports.as_ref().and_then(|r| r.total).map(|t| t as usize);
    let pagination = use_stored_pagination("importer-reports", total);
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let (reports, error) = (reports.clone(), error.clone());
        use_effect_with(
            (
                props.name.clone(),
                props.generation,
                pagination.control,
                token.clone(),
            ),
            move |(name, _, control, token)| {
                let (name, control, token) = (name.clone(), *control, token.clone());
                spawn_local(async move {
                    match api::fetch_importer_reports(
                        &name,
                        control.page * control.per_page,
                        control.per_page,
                        token.as_deref(),
                    )
                    .await
                    {
                        Ok(result) => {
                            reports.set(Some(result));
                            error.set(None);
                        }
                        Err(e) => error.set(Some(format!("Failed to load the reports: {e}"))),
                    }
                });
            },
        );
    }

    let header = html_nested! {
        <TableHeader<ReportColumn>>
            <TableColumn<ReportColumn> label="Created" index={ReportColumn::Created} />
            <TableColumn<ReportColumn> label="Items" index={ReportColumn::Items} />
            <TableColumn<ReportColumn> label="Error" index={ReportColumn::Error} />
        </TableHeader<ReportColumn>>
    };

    html! {
        <>
            if let Some(err) = &*error {
                <Alert title="Error" r#type={AlertType::Danger} inline=true><p>{ err }</p></Alert>
            }
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem r#type={ToolbarItemType::Pagination}>
                        <SimplePagination pagination={pagination.clone()} {total} />
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>
            <ComposableTable mode={TableMode::Compact}>
                { header }
                { for reports.iter().flat_map(|r| &r.items).map(|report| {
                    let messages = report_messages(report);
                    let items = report
                        .report
                        .as_ref()
                        .and_then(|r| r.get("numberOfItems"))
                        .and_then(Value::as_u64)
                        .map(|n| n.to_string())
                        .unwrap_or("-".into());
                    html! {
                        <TableBody key={report.id.clone()}>
                            <TableRow>
                                <TableData data_label="Created">{ timestamp(&report.creation) }</TableData>
                                <TableData data_label="Items">{ items }</TableData>
                                <TableData data_label="Error">{ report.error.clone().unwrap_or_default() }</TableData>
                            </TableRow>
                            if !messages.is_empty() {
                                <TableRow>
                                    <TableData colspan={3}>
                                        <ExpandableSection toggle_text_hidden={format!("Show {} messages", messages.len())} toggle_text_expanded="Hide messages">
                                            <ul>{ for messages.iter().map(|m| html! { <li>{ m }</li> }) }</ul>
                                        </ExpandableSection>
                                    </TableData>
                                </TableRow>
                            }
                        </TableBody>
                    }
                }) }
            </ComposableTable>
            if reports.as_ref().is_some_and(|r| r.items.is_empty()) {
                <EmptyState title="No reports" icon={Icon::Search} size={Size::Large}>
                    { "The importer has not completed a run yet." }
                </EmptyState>
            }
        </>
    }
}

#[derive(Clone, PartialEq, Properties)]
struct ConfigurationProps {
    name: String,
}

/// The editable configuration of an importer.
///
/// Loaded once, with its revision: saving fails if the importer changed meanwhile, which
/// includes the state updates of a run.
#[function_component(Configuration)]
fn configuration(props: &ConfigurationProps) -> Html {
    let loaded = use_state(|| None::<(String, Option<String>)>);
    let error = use_state(|| None::<String>);
    let saved = use_state(|| false);
    // bumped to reload the configuration
    let generation = use_state(|| 0u32);
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let (loaded, error) = (loaded.clone(), error.clone());
        let token = token.clone();
        use_effect_with((props.name.clone(), *generation), move |(name, _)| {
            let name = name.clone();
            loaded.set(None);
            spawn_local(async move {
                match api::fetch_importer(&name, token.as_deref()).await {
                    Ok((importer, revision)) => {
                        let text = serde_json::to_string_pretty(&importer.configuration)
                            .unwrap_or_default();
                        loaded.set(Some((text, revision)));
                    }
                    Err(e) => error.set(Some(format!("Failed to load the configuration: {e}"))),
                }
            });
        });
    }

    let reload = {
        let (generation, error, saved) = (generation.clone(), error.clone(), saved.clone());
        Callback::from(move |_: MouseEvent| {
            error.set(None);
            saved.set(false);
            generation.set(generation.wrapping_add(1));
        })
    };
    // reload for the new revision, keeping the message
    let on_saved = {
        let (generation, error, saved) = (generation.clone(), error.clone(), saved.clone());
        Callback::from(move |()| {
            error.set(None);
            saved.set(true);
            generation.set(generation.wrapping_add(1));
        })
    };

    html! {
        <Stack gutter=true>
            if let Some(err) = &*error {
                <Alert title="Unable to save" r#type={AlertType::Danger} inline=true><p>{ err }</p></Alert>
            }
            if *saved {
                <Alert title="Configuration saved" r#type={AlertType::Success} inline=true />
            }
            if let Some((text, revision)) = &*loaded {
                <ConfigurationEditor
                    key={*generation}
                    name={props.name.clone()}
                    text={text.clone()}
                    revision={revision.clone()}
                    {error}
                    {on_saved}
                    {reload}
                />
            } else if error.is_none() {
                <Bullseye><Spinner /></Bullseye>
            }
        </Stack>
    }
}

#[derive(Clone, PartialEq, Properties)]
struct ConfigurationEditorProps {
    name: String,
    text: String,
    revision: Option<String>,
    error: UseStateHandle<Option<String>>,
    on_saved: Callback<()>,
    reload: Callback<MouseEvent>,
}

#[function_component(ConfigurationEditor)]
fn configuration_editor(props: &ConfigurationEditorProps) -> Html {
    let model = use_json_model(&props.text);
    let saving = use_state(|| false);
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());

    let save = {
        let (name, revision) = (props.name.clone(), props.revision.clone());
        let (error, on_saved, saving, model) = (
            props.error.clone(),
            props.on_saved.clone(),
            saving.clone(),
            model.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let config = match parse_config(model.as_ref()) {
                Ok(config) => config,
                Err(e) => return error.set(Some(e)),
            };
            let (name, revision, token) = (name.clone(), revision.clone(), token.clone());
            let (error, on_saved, saving) = (error.clone(), on_saved.clone(), saving.clone());
            saving.set(true);
            spawn_local(async move {
                match api::update_importer(&name, revision.as_deref(), &config, token.as_deref())
                    .await
                {
                    Ok(()) => on_saved.emit(()),
                    Err(api::ApiError::Http { status: 412, .. }) => error.set(Some(
                        "The importer changed since it was loaded, e.g. by a run. Reload, and apply your changes again."
                            .into(),
                    )),
                    Err(e) => error.set(Some(e.to_string())),
                }
                saving.set(false);
            });
        })
    };

    html! {
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem>
                        <Button variant={ButtonVariant::Primary} onclick={save} disabled={*saving}>{ "Save" }</Button>
                    </ToolbarItem>
                    <ToolbarItem>
                        <Button variant={ButtonVariant::Secondary} onclick={props.reload.clone()} disabled={*saving}>{ "Reload" }</Button>
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>
            <JsonEditor {model} />
        </>
    }
}
