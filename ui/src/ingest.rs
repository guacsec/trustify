use crate::{api, model::IngestResult};
use patternfly_yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[function_component(IngestPage)]
pub fn ingest_page() -> Html {
    let result = use_state(|| Option::<IngestResult>::None);
    let loading = use_state(|| false);
    let error = use_state(|| Option::<String>::None);
    let input = use_state(String::new);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    let on_ingest = {
        let result = result.clone();
        let loading = loading.clone();
        let error = error.clone();
        let input = input.clone();
        let token = token.clone();
        Callback::from(move |_: ()| {
            let url = input.trim().to_string();
            if url.is_empty() {
                return;
            }
            let result = result.clone();
            let loading = loading.clone();
            let error = error.clone();
            let token = token.clone();
            spawn_local(async move {
                loading.set(true);
                error.set(None);
                result.set(None);
                match api::ingest_from_url(&url, token.as_deref()).await {
                    Ok(data) => result.set(Some(data)),
                    Err(e) => error.set(Some(e.to_string())),
                }
                loading.set(false);
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
        <PageSection>
            <Title level={Level::H1}>
                { "Ingest from URL" }
            </Title>
            <p>{ "Enter the URL of a CSAF advisory document to download and ingest." }</p>
            <br />

            <Form {onsubmit}>
                <FormGroup label="Document URL">
                    <TextInput
                        placeholder="https://example.com/advisory.json"
                        value={(*input).clone()}
                        {onchange}
                    />
                </FormGroup>
                <ActionGroup>
                    <Button
                        variant={ButtonVariant::Primary}
                        label="Ingest"
                        {onclick}
                        loading={*loading}
                        disabled={*loading}
                    />
                </ActionGroup>
            </Form>

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
struct IngestSuccessProps {
    result: IngestResult,
}

#[function_component(IngestSuccess)]
fn ingest_success(props: &IngestSuccessProps) -> Html {
    let r = &props.result;

    if r.duplicate {
        return html! {
            <Alert title="Document already exists" r#type={AlertType::Info} inline=true>
                <p>{ format!("Advisory {} was already ingested.", r.id) }</p>
            </Alert>
        };
    }

    html! {
        <>
            <Alert title="Advisory ingested" r#type={AlertType::Success} inline=true>
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
