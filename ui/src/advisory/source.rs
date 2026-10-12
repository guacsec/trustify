//! The source document of an advisory, as text.

use crate::monaco::ensure_environment;
use ::monaco::{sys::editor::IStandaloneEditorConstructionOptions, yew::CodeEditor};
use gloo_file::{Blob, ObjectUrl};
use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct SourceTabProps {
    pub document: Rc<String>,
    /// The file name to offer when downloading the document.
    pub file_name: AttrValue,
}

/// Read-only editor options for the text.
fn editor_options(text: &str, language: &str) -> IStandaloneEditorConstructionOptions {
    let options = IStandaloneEditorConstructionOptions::default();
    options.set_value(Some(text));
    options.set_language(Some(language));
    options.set_theme(Some("vs"));
    options.set_read_only(Some(true));
    options.set_automatic_layout(Some(true));
    options.set_scroll_beyond_last_line(Some(false));
    options
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

    // Changing the options re-creates the editor, so they only change with the text.
    let options = use_memo(
        (props.document.clone(), pretty.clone(), *formatted),
        |(doc, pretty, formatted)| match (&**pretty, formatted) {
            (Some(pretty), true) => editor_options(pretty, "json"),
            (Some(_), false) => editor_options(doc, "json"),
            (None, _) => editor_options(doc, "plaintext"),
        },
    );

    let onformat = {
        let formatted = formatted.clone();
        Callback::from(move |checked| formatted.set(checked))
    };

    ensure_environment();

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
            <CodeEditor classes="trustify-source-editor" options={(*options).clone()} />
        </>
    }
}
