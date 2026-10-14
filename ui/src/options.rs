//! Correlation options: per publisher, e.g. whether versionless PURLs mean all versions.

use crate::{
    api,
    model::{CorrelationOption, CorrelationOptionData, CorrelationOptionKey},
};
use patternfly_yew::prelude::*;
use serde_json::Value;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

/// A change of the options, resolving to an error message on failure.
type Change = Pin<Box<dyn Future<Output = Result<(), String>>>>;

#[derive(Copy, Clone, Eq, PartialEq)]
enum Column {
    Key,
    Publisher,
    Value,
    Reason,
    Actions,
}

/// A row of the options table, with the actions on it.
#[derive(Clone, PartialEq)]
struct OptionEntry {
    option: CorrelationOption,
    /// Set the value of an option.
    on_value: Callback<(CorrelationOption, Value)>,
    /// Delete an option.
    on_delete: Callback<Uuid>,
}

impl TableEntryRenderer<Column> for OptionEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        let data = &self.option.data;
        match context.column {
            Column::Key => html!(<code>{ data.key.as_str() }</code>).into(),
            Column::Publisher => html!(&data.publisher_namespace).into(),
            Column::Value => match data.value.as_bool() {
                Some(checked) => {
                    let onchange = {
                        let option = self.option.clone();
                        let on_value = self.on_value.clone();
                        Callback::from(move |checked: bool| {
                            on_value.emit((option.clone(), Value::Bool(checked)))
                        })
                    };
                    html!(<Switch {checked} {onchange} aria_label="Enabled" />).into()
                }
                None => html!(<code>{ data.value.to_string() }</code>).into(),
            },
            Column::Reason => html!(data.reason.as_deref().unwrap_or("-")).into(),
            Column::Actions => {
                let onclick = {
                    let id = self.option.id;
                    let on_delete = self.on_delete.clone();
                    Callback::from(move |_: MouseEvent| on_delete.emit(id))
                };
                html!(
                    <Button
                        variant={ButtonVariant::Plain}
                        icon={Icon::Trash}
                        aria_label="Delete"
                        {onclick}
                    />
                )
                .into()
            }
        }
    }
}

#[function_component(OptionsPage)]
pub fn options_page() -> Html {
    let options = use_state(Vec::<CorrelationOption>::new);
    let loading = use_state(|| true);
    let error = use_state(|| Option::<String>::None);
    // bumped to reload the options after a change
    let generation = use_state(|| 0u32);

    let latest_token = use_latest_access_token();
    let token: Option<String> = latest_token.as_ref().and_then(|t| t.access_token());

    {
        let options = options.clone();
        let loading = loading.clone();
        let error = error.clone();
        let token = token.clone();
        use_effect_with(*generation, move |_| {
            spawn_local(async move {
                loading.set(true);
                match api::fetch_options(token.as_deref()).await {
                    Ok(result) => options.set(result.items),
                    Err(e) => error.set(Some(format!("Failed to load the options: {e}"))),
                }
                loading.set(false);
            });
        });
    }

    // run a change, then reload, or show its error
    let change = {
        let error = error.clone();
        let generation = generation.clone();
        Callback::from(move |change: Change| {
            let error = error.clone();
            let generation = generation.clone();
            spawn_local(async move {
                match change.await {
                    Ok(()) => error.set(None),
                    Err(e) => error.set(Some(e)),
                }
                generation.set(generation.wrapping_add(1));
            });
        })
    };

    let on_value = {
        let change = change.clone();
        let token = token.clone();
        Callback::from(move |(option, value): (CorrelationOption, Value)| {
            let token = token.clone();
            change.emit(Box::pin(async move {
                let data = CorrelationOptionData {
                    value,
                    ..option.data
                };
                api::update_option(option.id, &data, token.as_deref())
                    .await
                    .map_err(|e| format!("Failed to update the option: {e}"))
            }));
        })
    };

    let on_delete = {
        let change = change.clone();
        let token = token.clone();
        Callback::from(move |id: Uuid| {
            let token = token.clone();
            change.emit(Box::pin(async move {
                api::delete_option(id, token.as_deref())
                    .await
                    .map_err(|e| format!("Failed to delete the option: {e}"))
            }));
        })
    };

    let on_create = {
        let change = change.clone();
        let token = token.clone();
        Callback::from(move |data: CorrelationOptionData| {
            let token = token.clone();
            change.emit(Box::pin(async move {
                api::create_option(&data, token.as_deref())
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("Failed to create the option: {e}"))
            }));
        })
    };

    let entries = use_memo((*options).clone(), {
        let on_value = on_value.clone();
        let on_delete = on_delete.clone();
        move |options| {
            options
                .iter()
                .map(|option| OptionEntry {
                    option: option.clone(),
                    on_value: on_value.clone(),
                    on_delete: on_delete.clone(),
                })
                .collect::<Vec<_>>()
        }
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Option" index={Column::Key} />
            <TableColumn<Column> label="Publisher namespace" index={Column::Publisher} />
            <TableColumn<Column> label="Value" index={Column::Value} />
            <TableColumn<Column> label="Reason" index={Column::Reason} />
            <TableColumn<Column> label="" index={Column::Actions} />
        </TableHeader<Column>>
    };

    html! {
        <PageSection>
            <Title level={Level::H1}>{ "Correlation Options" }</Title>
            <p>
                { "Options enable an interpretation of the advisories of a publisher, e.g. that \
                   their versionless PURLs mean all versions. Evidence depending on an option names \
                   it. A change applies to documents extracted afterwards." }
            </p>
            <br />

            if let Some(err) = &*error {
                <Alert title="Error" r#type={AlertType::Danger} inline=true>
                    <p>{ err.clone() }</p>
                </Alert>
                <br />
            }

            if *loading && options.is_empty() {
                <Bullseye><Spinner /></Bullseye>
            } else {
                <Table<Column, UseTableData<Column, MemoizedTableModel<OptionEntry>>>
                    {header}
                    {entries}
                    mode={TableMode::Compact}
                />
            }

            <br />
            <Title level={Level::H2}>{ "Add option" }</Title>
            <AddOption {on_create} />
        </PageSection>
    }
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct AddOptionProps {
    on_create: Callback<CorrelationOptionData>,
}

/// A form adding an option.
#[function_component(AddOption)]
fn add_option(props: &AddOptionProps) -> Html {
    let key = use_state(|| CorrelationOptionKey::VersionlessPurl);
    let namespace = use_state(String::new);
    let enabled = use_state(|| true);
    let reason = use_state(String::new);

    let onsubmit = {
        let (key, namespace, enabled, reason) = (
            key.clone(),
            namespace.clone(),
            enabled.clone(),
            reason.clone(),
        );
        let on_create = props.on_create.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let publisher_namespace = namespace.trim().to_string();
            if publisher_namespace.is_empty() {
                return;
            }
            let reason_text = reason.trim();
            on_create.emit(CorrelationOptionData {
                key: *key,
                publisher_namespace,
                value: Value::Bool(*enabled),
                reason: (!reason_text.is_empty()).then(|| reason_text.to_string()),
            });
            namespace.set(String::new());
            reason.set(String::new());
        })
    };

    let onselect = {
        let key = key.clone();
        Callback::from(move |value: CorrelationOptionKey| key.set(value))
    };
    let on_namespace = {
        let namespace = namespace.clone();
        Callback::from(move |value: String| namespace.set(value))
    };
    let on_enabled = {
        let enabled = enabled.clone();
        Callback::from(move |value: bool| enabled.set(value))
    };
    let on_reason = {
        let reason = reason.clone();
        Callback::from(move |value: String| reason.set(value))
    };

    html! {
        <Form {onsubmit}>
            <FormGroup label="Option">
                <SimpleSelect<CorrelationOptionKey>
                    entries={CorrelationOptionKey::ALL.to_vec()}
                    selected={*key}
                    {onselect}
                />
            </FormGroup>
            <FormGroup label="Publisher namespace" required=true>
                <TextInput
                    placeholder="https://www.example.com"
                    value={(*namespace).clone()}
                    onchange={on_namespace}
                />
            </FormGroup>
            <FormGroup label="Enabled">
                <Switch checked={*enabled} onchange={on_enabled} aria_label="Enabled" />
            </FormGroup>
            <FormGroup label="Reason">
                <TextInput
                    placeholder="Why the option is set, shown with the evidence"
                    value={(*reason).clone()}
                    onchange={on_reason}
                />
            </FormGroup>
            <ActionGroup>
                <Button variant={ButtonVariant::Primary} label="Add" r#type={ButtonType::Submit} />
            </ActionGroup>
        </Form>
    }
}
