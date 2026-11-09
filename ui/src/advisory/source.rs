//! The source document of an advisory, as text.

use gloo_file::{Blob, ObjectUrl};
use monaco_yew::{EditorOptions, MonacoEditor};
use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct SourceTabProps {
    pub document: Rc<String>,
    /// The file name to offer when downloading the document.
    pub file_name: AttrValue,
}

#[function_component(SourceTab)]
pub fn source_tab(props: &SourceTabProps) -> Html {
    let formatted = use_state_eq(|| true);

    // Not every format is JSON, so failing to parse only means there is nothing to format.
    let pretty = use_memo(props.document.clone(), |doc| {
        serde_json::from_str::<serde_json::Value>(doc)
            .ok()
            .and_then(|value| serde_json::to_string_pretty(&value).ok())
    });

    // The download is served from the fetched text: a plain link to the API would lack the
    // access token.
    let download = use_memo(props.document.clone(), |doc| {
        ObjectUrl::from(Blob::new(doc.as_str()))
    });

    let text = match (&*pretty, *formatted) {
        (Some(pretty), true) => pretty.clone(),
        _ => props.document.to_string(),
    };
    let text = AttrValue::from(text);
    let language = if pretty.is_some() {
        "json"
    } else {
        "plaintext"
    };
    let mut options = EditorOptions::default();
    options.read_only = true;

    let onformat = {
        let formatted = formatted.clone();
        Callback::from(move |checked| formatted.set(checked))
    };

    html! {
        <>
            <Toolbar>
                <ToolbarContent>
                    { for pretty.is_some().then(|| html_nested! {
                        <ToolbarItem>
                            <Switch checked={*formatted} onchange={onformat.clone()} label="Format JSON" />
                        </ToolbarItem>
                    }) }
                    <ToolbarItem>
                        <a href={download.to_string()} download={props.file_name.clone()}>
                            { Icon::Download } { " Download" }
                        </a>
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>
            <MonacoEditor key={text.as_str()} class="trustify-source-editor" style="height: 70vh;" initial_value={text.clone()} {language} {options} />
        </>
    }
}
