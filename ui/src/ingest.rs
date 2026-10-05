use crate::{api, model::IngestResult};
use gloo_file::{File, FileList, futures::read_as_bytes};
use patternfly_yew::prelude::*;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;
use web_sys::{DragEvent, HtmlInputElement};
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Copy, PartialEq, Eq)]
enum IngestTab {
    File,
    Url,
}

/// The outcome of ingesting a single document.
#[derive(Clone, Debug, PartialEq)]
struct IngestOutcome {
    /// The file name or URL of the document.
    name: String,
    result: Result<IngestResult, String>,
}

enum IngestAction {
    Start,
    Outcome(IngestOutcome),
    Done,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct IngestState {
    loading: bool,
    outcomes: Vec<IngestOutcome>,
}

impl Reducible for IngestState {
    type Action = IngestAction;

    fn reduce(self: Rc<Self>, action: Self::Action) -> Rc<Self> {
        let mut state = (*self).clone();
        match action {
            IngestAction::Start => {
                state.loading = true;
                state.outcomes.clear();
            }
            IngestAction::Outcome(outcome) => state.outcomes.push(outcome),
            IngestAction::Done => state.loading = false,
        }
        Rc::new(state)
    }
}

#[function_component(IngestPage)]
pub fn ingest_page() -> Html {
    let tab = use_state(|| IngestTab::File);
    let state = use_reducer(IngestState::default);

    let on_start = {
        let state = state.dispatcher();
        Callback::from(move |()| state.dispatch(IngestAction::Start))
    };

    let on_outcome = {
        let state = state.dispatcher();
        Callback::from(move |outcome| state.dispatch(IngestAction::Outcome(outcome)))
    };

    let on_done = {
        let state = state.dispatcher();
        Callback::from(move |()| state.dispatch(IngestAction::Done))
    };

    let onselect = {
        let tab = tab.clone();
        Callback::from(move |index: IngestTab| tab.set(index))
    };

    html! {
        <PageSection>
            <Title level={Level::H1}>
                { "Ingest Document" }
            </Title>
            <p>{ "Upload any supported documents (SBOM or advisory), optionally compressed (xz, gzip, bzip2). The format and compression are auto-detected." }</p>
            <br />

            <Tabs<IngestTab> selected={*tab} {onselect}>
                <Tab<IngestTab> index={IngestTab::File} title="File Upload">
                    <TabContent>
                        <TabContentBody padding=true>
                            <FileUploadSection
                                loading={state.loading}
                                on_start={on_start.clone()}
                                on_outcome={on_outcome.clone()}
                                on_done={on_done.clone()}
                            />
                        </TabContentBody>
                    </TabContent>
                </Tab<IngestTab>>
                <Tab<IngestTab> index={IngestTab::Url} title="From URL">
                    <TabContent>
                        <TabContentBody padding=true>
                            <UrlIngestSection
                                loading={state.loading}
                                on_start={on_start.clone()}
                                on_outcome={on_outcome.clone()}
                                on_done={on_done.clone()}
                            />
                        </TabContentBody>
                    </TabContent>
                </Tab<IngestTab>>
            </Tabs<IngestTab>>

            <br />

            <div style="display: flex; flex-direction: column; gap: var(--pf-t--global--spacer--md);">
                { for state.outcomes.iter().map(|outcome| html! {
                    <IngestOutcomeView outcome={outcome.clone()} />
                }) }
            </div>

            if state.loading {
                <br />
                <Bullseye>
                    <Spinner />
                </Bullseye>
            }
        </PageSection>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct FileUploadSectionProps {
    loading: bool,
    on_start: Callback<()>,
    on_outcome: Callback<IngestOutcome>,
    on_done: Callback<()>,
}

#[function_component(FileUploadSection)]
fn file_upload_section(props: &FileUploadSectionProps) -> Html {
    let selected_files = use_state(Vec::<File>::new);
    let drag_over = use_state(|| false);
    let file_input_ref = use_node_ref();

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    let on_files_selected = {
        let selected_files = selected_files.clone();
        Callback::from(move |files: FileList| {
            let mut selected = (*selected_files).clone();
            selected.extend(files.iter().cloned());
            selected_files.set(selected);
        })
    };

    let on_input_change = {
        let on_files_selected = on_files_selected.clone();
        Callback::from(move |e: Event| {
            let input: HtmlInputElement = e.target_unchecked_into();
            if let Some(files) = input.files() {
                on_files_selected.emit(FileList::from(files));
            }
            // allow selecting the same file again after it was removed
            input.set_value("");
        })
    };

    let on_browse = {
        let file_input_ref = file_input_ref.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(input) = file_input_ref.cast::<HtmlInputElement>() {
                input.click();
            }
        })
    };

    let ondragover = {
        let drag_over = drag_over.clone();
        Callback::from(move |e: DragEvent| {
            e.prevent_default();
            drag_over.set(true);
        })
    };

    let ondragleave = {
        let drag_over = drag_over.clone();
        Callback::from(move |_: DragEvent| {
            drag_over.set(false);
        })
    };

    let ondrop = {
        let drag_over = drag_over.clone();
        let on_files_selected = on_files_selected.clone();
        Callback::from(move |e: DragEvent| {
            e.prevent_default();
            drag_over.set(false);
            if let Some(files) = e.data_transfer().and_then(|dt| dt.files()) {
                on_files_selected.emit(FileList::from(files));
            }
        })
    };

    let on_upload = {
        let selected_files = selected_files.clone();
        let on_start = props.on_start.clone();
        let on_outcome = props.on_outcome.clone();
        let on_done = props.on_done.clone();
        let token = token.clone();
        Callback::from(move |_: MouseEvent| {
            let files = (*selected_files).clone();
            if files.is_empty() {
                return;
            }
            on_start.emit(());
            let selected_files = selected_files.clone();
            let on_outcome = on_outcome.clone();
            let on_done = on_done.clone();
            let token = token.clone();
            spawn_local(async move {
                let mut failed = Vec::new();
                for file in files {
                    let result = match read_as_bytes(&file).await {
                        Ok(bytes) => api::upload_document(&bytes, token.as_deref())
                            .await
                            .map_err(|e| e.to_string()),
                        Err(e) => Err(format!("Failed to read file: {e}")),
                    };
                    let name = file.name();
                    if result.is_err() {
                        failed.push(file);
                    }
                    on_outcome.emit(IngestOutcome { name, result });
                }
                // keep failed files selected, so that they can be retried
                selected_files.set(failed);
                on_done.emit(());
            });
        })
    };

    let on_clear = {
        let selected_files = selected_files.clone();
        Callback::from(move |_: MouseEvent| {
            selected_files.set(Vec::new());
        })
    };

    let on_remove = {
        let selected_files = selected_files.clone();
        Callback::from(move |index: usize| {
            let mut selected = (*selected_files).clone();
            if index < selected.len() {
                selected.remove(index);
            }
            selected_files.set(selected);
        })
    };

    let total_size: u64 = selected_files.iter().map(|f| f.size()).sum();

    html! {
        <>
            <input
                ref={file_input_ref}
                type="file"
                accept=".json,.xml,.yaml,.yml,.xz,.gz,.bz2"
                multiple=true
                onchange={on_input_change}
                style="display: none;"
            />
            <FileUpload drag_over={*drag_over}>
                <FileUploadSelect>
                    <div
                        {ondragover}
                        {ondragleave}
                        {ondrop}
                        style="padding: var(--pf-t--global--spacer--xl); text-align: center; border: 2px dashed var(--pf-t--global--border--color--default); border-radius: var(--pf-t--global--border--radius--small);"
                    >
                        if selected_files.is_empty() {
                            <p>{ "Drag and drop files here, or" }</p>
                            <br />
                            <Button
                                variant={ButtonVariant::Secondary}
                                label="Browse..."
                                onclick={on_browse}
                            />
                        } else {
                            <p>
                                <strong>{ format!("Selected {} file(s)", selected_files.len()) }</strong>
                                { format!(" ({})", format_size(total_size)) }
                            </p>
                            <ul style="list-style: none; padding: 0; margin: var(--pf-t--global--spacer--sm) 0;">
                                { for selected_files.iter().enumerate().map(|(index, file)| {
                                    let on_remove = on_remove.clone();
                                    html! {
                                        <li>
                                            { file.name() }
                                            { format!(" ({})", format_size(file.size())) }
                                            <Button
                                                variant={ButtonVariant::Link}
                                                label="Remove"
                                                onclick={move |_: MouseEvent| on_remove.emit(index)}
                                                disabled={props.loading}
                                            />
                                        </li>
                                    }
                                }) }
                            </ul>
                            <div style="display: flex; gap: var(--pf-t--global--spacer--md); justify-content: center;">
                                <Button
                                    variant={ButtonVariant::Primary}
                                    label="Upload"
                                    onclick={on_upload}
                                    loading={props.loading}
                                    disabled={props.loading}
                                />
                                <Button
                                    variant={ButtonVariant::Secondary}
                                    label="Add more..."
                                    onclick={on_browse}
                                    disabled={props.loading}
                                />
                                <Button
                                    variant={ButtonVariant::Secondary}
                                    label="Clear"
                                    onclick={on_clear}
                                    disabled={props.loading}
                                />
                            </div>
                        }
                    </div>
                </FileUploadSelect>
            </FileUpload>
        </>
    }
}

fn format_size(bytes: u64) -> String {
    format!("{:.1} KB", bytes as f64 / 1024.0)
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct UrlIngestSectionProps {
    loading: bool,
    on_start: Callback<()>,
    on_outcome: Callback<IngestOutcome>,
    on_done: Callback<()>,
}

#[function_component(UrlIngestSection)]
fn url_ingest_section(props: &UrlIngestSectionProps) -> Html {
    let input = use_state(String::new);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    let on_ingest = {
        let input = input.clone();
        let on_start = props.on_start.clone();
        let on_outcome = props.on_outcome.clone();
        let on_done = props.on_done.clone();
        let token = token.clone();
        Callback::from(move |_: ()| {
            let url = input.trim().to_string();
            if url.is_empty() {
                return;
            }
            on_start.emit(());
            let on_outcome = on_outcome.clone();
            let on_done = on_done.clone();
            let token = token.clone();
            spawn_local(async move {
                let result = api::ingest_from_url(&url, token.as_deref())
                    .await
                    .map_err(|e| e.to_string());
                on_outcome.emit(IngestOutcome { name: url, result });
                on_done.emit(());
            });
        })
    };

    let onsubmit = {
        let on_ingest = on_ingest.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            on_ingest.emit(());
        })
    };

    let onclick = {
        let on_ingest = on_ingest.clone();
        Callback::from(move |_: MouseEvent| {
            on_ingest.emit(());
        })
    };

    let onchange = {
        let input = input.clone();
        Callback::from(move |value: String| input.set(value))
    };

    html! {
        <Form {onsubmit}>
            <FormGroup label="Document URL">
                <TextInput
                    placeholder="https://example.com/document.json"
                    value={(*input).clone()}
                    {onchange}
                />
            </FormGroup>
            <ActionGroup>
                <Button
                    variant={ButtonVariant::Primary}
                    label="Ingest"
                    {onclick}
                    loading={props.loading}
                    disabled={props.loading}
                />
            </ActionGroup>
        </Form>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct IngestOutcomeViewProps {
    outcome: IngestOutcome,
}

#[function_component(IngestOutcomeView)]
fn ingest_outcome_view(props: &IngestOutcomeViewProps) -> Html {
    let name = &props.outcome.name;

    let r = match &props.outcome.result {
        Ok(r) => r,
        Err(err) => {
            return html! {
                <Alert title={format!("Ingestion failed: {name}")} r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
            };
        }
    };

    if r.duplicate {
        return html! {
            <Alert title={format!("Document already exists: {name}")} r#type={AlertType::Info} inline=true>
                <p>{ format!("Document {} was already ingested.", r.id) }</p>
            </Alert>
        };
    }

    html! {
        <>
            <Alert title={format!("Document ingested: {name}")} r#type={AlertType::Success} inline=true>
                <p>{ format!("ID: {}", r.id) }</p>
                if let Some(doc_id) = &r.document_id {
                    <p>{ format!("Document ID: {doc_id}") }</p>
                }
            </Alert>
            if !r.warnings.is_empty() {
                <Alert title={format!("Warnings: {name}")} r#type={AlertType::Warning} inline=true>
                    <ul>
                        { for r.warnings.iter().map(|w| html! { <li>{ w }</li> }) }
                    </ul>
                </Alert>
            }
        </>
    }
}
