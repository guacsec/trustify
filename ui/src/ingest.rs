use crate::{api, model::IngestResult};
use gloo_file::{File, futures::read_as_bytes};
use patternfly_yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{DragEvent, HtmlInputElement};
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Copy, PartialEq, Eq)]
enum IngestTab {
    File,
    Url,
}

#[function_component(IngestPage)]
pub fn ingest_page() -> Html {
    let tab = use_state(|| IngestTab::File);
    let result = use_state(|| Option::<IngestResult>::None);
    let loading = use_state(|| false);
    let error = use_state(|| Option::<String>::None);

    let on_result = {
        let result = result.clone();
        let loading = loading.clone();
        let error = error.clone();
        Callback::from(move |r: Result<IngestResult, String>| {
            match r {
                Ok(data) => result.set(Some(data)),
                Err(e) => error.set(Some(e)),
            }
            loading.set(false);
        })
    };

    let on_start = {
        let loading = loading.clone();
        let error = error.clone();
        let result = result.clone();
        Callback::from(move |()| {
            loading.set(true);
            error.set(None);
            result.set(None);
        })
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
            <p>{ "Upload any supported document (SBOM or advisory). The format is auto-detected." }</p>
            <br />

            <Tabs<IngestTab> selected={*tab} {onselect}>
                <Tab<IngestTab> index={IngestTab::File} title="File Upload">
                    <TabContent>
                        <TabContentBody padding=true>
                            <FileUploadSection
                                loading={*loading}
                                on_start={on_start.clone()}
                                on_result={on_result.clone()}
                            />
                        </TabContentBody>
                    </TabContent>
                </Tab<IngestTab>>
                <Tab<IngestTab> index={IngestTab::Url} title="From URL">
                    <TabContent>
                        <TabContentBody padding=true>
                            <UrlIngestSection
                                loading={*loading}
                                on_start={on_start.clone()}
                                on_result={on_result.clone()}
                            />
                        </TabContentBody>
                    </TabContent>
                </Tab<IngestTab>>
            </Tabs<IngestTab>>

            <br />

            if *loading {
                <Bullseye>
                    <Spinner />
                </Bullseye>
            } else if let Some(err) = &*error {
                <Alert title="Ingestion failed" r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
            } else if let Some(data) = &*result {
                <IngestSuccess result={data.clone()} />
            }
        </PageSection>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct FileUploadSectionProps {
    loading: bool,
    on_start: Callback<()>,
    on_result: Callback<Result<IngestResult, String>>,
}

#[function_component(FileUploadSection)]
fn file_upload_section(props: &FileUploadSectionProps) -> Html {
    let selected_file = use_state(|| Option::<File>::None);
    let drag_over = use_state(|| false);
    let file_input_ref = use_node_ref();

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    let on_file_selected = {
        let selected_file = selected_file.clone();
        Callback::from(move |file: File| {
            selected_file.set(Some(file));
        })
    };

    let on_input_change = {
        let on_file_selected = on_file_selected.clone();
        Callback::from(move |e: Event| {
            let input: HtmlInputElement = e.target_unchecked_into();
            if let Some(files) = input.files() {
                if let Some(file) = files.get(0) {
                    on_file_selected.emit(File::from(file));
                }
            }
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
        let on_file_selected = on_file_selected.clone();
        Callback::from(move |e: DragEvent| {
            e.prevent_default();
            drag_over.set(false);
            if let Some(dt) = e.data_transfer() {
                if let Some(files) = dt.files() {
                    if let Some(file) = files.get(0) {
                        on_file_selected.emit(File::from(file));
                    }
                }
            }
        })
    };

    let on_upload = {
        let selected_file = selected_file.clone();
        let file_input_ref = file_input_ref.clone();
        let on_start = props.on_start.clone();
        let on_result = props.on_result.clone();
        let token = token.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(file) = (*selected_file).clone() {
                on_start.emit(());
                let selected_file = selected_file.clone();
                let file_input_ref = file_input_ref.clone();
                let on_result = on_result.clone();
                let token = token.clone();
                spawn_local(async move {
                    let result = match read_as_bytes(&file).await {
                        Ok(bytes) => match api::upload_document(&bytes, token.as_deref()).await {
                            Ok(data) => Ok(data),
                            Err(e) => Err(e.to_string()),
                        },
                        Err(e) => Err(format!("Failed to read file: {e}")),
                    };
                    let ok = result.is_ok();
                    on_result.emit(result);
                    if ok {
                        selected_file.set(None);
                        if let Some(input) = file_input_ref.cast::<HtmlInputElement>() {
                            input.set_value("");
                        }
                    }
                });
            }
        })
    };

    let on_clear = {
        let selected_file = selected_file.clone();
        let file_input_ref = file_input_ref.clone();
        Callback::from(move |_: MouseEvent| {
            selected_file.set(None);
            if let Some(input) = file_input_ref.cast::<HtmlInputElement>() {
                input.set_value("");
            }
        })
    };

    html! {
        <>
            <input
                ref={file_input_ref}
                type="file"
                accept=".json,.xml,.yaml,.yml"
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
                        if let Some(file) = &*selected_file {
                            <p>
                                <strong>{ "Selected: " }</strong>
                                { file.name() }
                                { format!(" ({:.1} KB)", file.size() as f64 / 1024.0) }
                            </p>
                            <br />
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
                                    label="Clear"
                                    onclick={on_clear}
                                    disabled={props.loading}
                                />
                            </div>
                        } else {
                            <p>{ "Drag and drop a file here, or" }</p>
                            <br />
                            <Button
                                variant={ButtonVariant::Secondary}
                                label="Browse..."
                                onclick={on_browse}
                            />
                        }
                    </div>
                </FileUploadSelect>
            </FileUpload>
        </>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct UrlIngestSectionProps {
    loading: bool,
    on_start: Callback<()>,
    on_result: Callback<Result<IngestResult, String>>,
}

#[function_component(UrlIngestSection)]
fn url_ingest_section(props: &UrlIngestSectionProps) -> Html {
    let input = use_state(String::new);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    let on_ingest = {
        let input = input.clone();
        let on_start = props.on_start.clone();
        let on_result = props.on_result.clone();
        let token = token.clone();
        Callback::from(move |_: ()| {
            let url = input.trim().to_string();
            if url.is_empty() {
                return;
            }
            on_start.emit(());
            let on_result = on_result.clone();
            let token = token.clone();
            spawn_local(async move {
                match api::ingest_from_url(&url, token.as_deref()).await {
                    Ok(data) => on_result.emit(Ok(data)),
                    Err(e) => on_result.emit(Err(e.to_string())),
                }
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
struct IngestSuccessProps {
    result: IngestResult,
}

#[function_component(IngestSuccess)]
fn ingest_success(props: &IngestSuccessProps) -> Html {
    let r = &props.result;

    if r.duplicate {
        return html! {
            <Alert title="Document already exists" r#type={AlertType::Info} inline=true>
                <p>{ format!("Document {} was already ingested.", r.id) }</p>
            </Alert>
        };
    }

    html! {
        <>
            <Alert title="Document ingested" r#type={AlertType::Success} inline=true>
                <p>{ format!("ID: {}", r.id) }</p>
                if let Some(doc_id) = &r.document_id {
                    <p>{ format!("Document ID: {doc_id}") }</p>
                }
            </Alert>
            if !r.warnings.is_empty() {
                <br />
                <Alert title="Warnings" r#type={AlertType::Warning} inline=true>
                    <ul>
                        { for r.warnings.iter().map(|w| html! { <li>{ w }</li> }) }
                    </ul>
                </Alert>
            }
        </>
    }
}
