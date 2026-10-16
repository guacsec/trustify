use crate::{api, weighting::text_field};
use patternfly_yew::prelude::*;
use trustify_api::correlation::{ProviderAlias, ProviderAliasData};
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AliasColumn {
    Provider,
    Identifiers,
    Actions,
}

#[derive(Clone, PartialEq)]
struct AliasEntry {
    alias: ProviderAlias,
    on_edit: Callback<ProviderAlias>,
    on_delete: Callback<Uuid>,
}

impl TableEntryRenderer<AliasColumn> for AliasEntry {
    fn render_cell(&self, context: CellContext<'_, AliasColumn>) -> Cell {
        match context.column {
            AliasColumn::Provider => html! {
                <strong style="overflow-wrap: anywhere;">{&self.alias.data.provider}</strong>
            }.into(),
            AliasColumn::Identifiers => html! {
                <Stack gutter=true>
                    {for self.alias.data.aliases.iter().map(|alias| {
                        let (kind,value)=alias.split_once(':').unwrap_or(("",alias));
                        let label=match kind {
                            "name"=>"Name",
                            "namespace"=>"Namespace",
                            "cve-org"=>"CVE organization",
                            "purl"=>"Package namespace",
                            "distro"=>"Distribution",
                            "cpe-vendor"=>"CPE vendor",
                            _=>"Identifier",
                        };
                        let value=if label=="Identifier" {alias.as_str()} else {value};
                        html!{
                            <StackItem>
                                <Flex space_items={[SpaceItems::Small]}>
                                    <FlexItem><Label label={label}/></FlexItem>
                                    <FlexItem><code style="overflow-wrap: anywhere;">{value}</code></FlexItem>
                                </Flex>
                            </StackItem>
                        }
                    })}
                </Stack>
            }.into(),
            AliasColumn::Actions => {
                let edit=self.on_edit.clone();let alias=self.alias.clone();
                let delete=self.on_delete.clone();let id=self.alias.id;
                html!{
                    <Flex space_items={[SpaceItems::Small]}>
                        <FlexItem><Button variant={ButtonVariant::Link}
                            aria_label={format!("Edit aliases for {}",self.alias.data.provider)}
                            onclick={Callback::from(move|_:MouseEvent|edit.emit(alias.clone()))}>{"Edit"}</Button></FlexItem>
                        <FlexItem><Button variant={ButtonVariant::Link}
                            aria_label={format!("Delete aliases for {}",self.alias.data.provider)}
                            onclick={Callback::from(move|_:MouseEvent|delete.emit(id))}>{"Delete"}</Button></FlexItem>
                    </Flex>
                }.into()
            }
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
struct ProviderAliasTableProps {
    aliases: Vec<ProviderAlias>,
    on_edit: Callback<ProviderAlias>,
    on_delete: Callback<Uuid>,
}

#[function_component(ProviderAliasTable)]
fn provider_alias_table(props: &ProviderAliasTableProps) -> Html {
    let entries = use_memo(props.clone(), |props| {
        let mut aliases = props.aliases.clone();
        aliases.sort_by(|a, b| a.data.provider.cmp(&b.data.provider));
        aliases
            .into_iter()
            .map(|alias| AliasEntry {
                alias,
                on_edit: props.on_edit.clone(),
                on_delete: props.on_delete.clone(),
            })
            .collect::<Vec<_>>()
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));
    if props.aliases.is_empty() {
        return html! {<p>{"No provider aliases configured."}</p>};
    }
    let header = html_nested! {
        <TableHeader<AliasColumn>>
            <TableColumn<AliasColumn> label="Provider" index={AliasColumn::Provider}/>
            <TableColumn<AliasColumn> label="Matching identifiers" index={AliasColumn::Identifiers}/>
            <TableColumn<AliasColumn> label="Actions" index={AliasColumn::Actions}/>
        </TableHeader<AliasColumn>>
    };
    html! {
        <Table<AliasColumn, UseTableData<AliasColumn, MemoizedTableModel<AliasEntry>>>
            {header} {entries} mode={TableMode::Compact}/>
    }
}

#[derive(Clone, PartialEq, Properties)]
struct AliasDialogProps {
    /// The alias to edit, or `None` to create one.
    alias: Option<ProviderAlias>,
    on_saved: Callback<()>,
}

/// Modal creating or editing one provider alias.
#[function_component(AliasDialog)]
fn alias_dialog(props: &AliasDialogProps) -> Html {
    let provider = use_state(|| {
        props
            .alias
            .as_ref()
            .map(|a| a.data.provider.clone())
            .unwrap_or_default()
    });
    let alias_text = use_state(|| {
        props
            .alias
            .as_ref()
            .map(|a| a.data.aliases.join("\n"))
            .unwrap_or_default()
    });
    let error = use_state(|| None::<String>);
    #[allow(clippy::expect_used)]
    let backdrop = use_backdrop().expect("AliasDialog requires BackdropViewer");
    let latest = use_latest_access_token();
    let token = latest.as_ref().and_then(|t| t.access_token());
    let close = {
        let backdrop = backdrop.clone();
        Callback::from(move |_: MouseEvent| backdrop.close())
    };
    let save = {
        let provider = provider.clone();
        let alias_text = alias_text.clone();
        let error = error.clone();
        let id = props.alias.as_ref().map(|a| a.id);
        let on_saved = props.on_saved.clone();
        Callback::from(move |_: MouseEvent| {
            let data = ProviderAliasData {
                provider: (*provider).clone(),
                aliases: alias_text
                    .lines()
                    .filter(|v| !v.trim().is_empty())
                    .map(str::to_string)
                    .collect(),
            };
            let token = token.clone();
            let error = error.clone();
            let backdrop = backdrop.clone();
            let on_saved = on_saved.clone();
            spawn_local(async move {
                match api::save_provider_alias(id, &data, token.as_deref()).await {
                    Ok(()) => {
                        backdrop.close();
                        on_saved.emit(());
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            })
        })
    };
    let title = if props.alias.is_some() {
        "Edit provider alias"
    } else {
        "Add provider alias"
    };
    let footer = html! {
        <>
            <Button variant={ButtonVariant::Primary} onclick={save}>{"Save"}</Button>
            <Button variant={ButtonVariant::Link} onclick={close}>{"Cancel"}</Button>
        </>
    };
    html! {
        <Modal {title} variant={ModalVariant::Medium} {footer}>
            <Form onsubmit={Callback::from(|event: SubmitEvent| event.prevent_default())}>
                if let Some(e)=&*error {<Alert title="Unable to save" r#type={AlertType::Danger} inline=true><p>{e}</p></Alert>}
                {text_field("Canonical provider",provider)}
                <FormGroup label="Aliases (one per line)">
                    <TextArea value={(*alias_text).clone()} rows={6} resize={ResizeOrientation::Vertical}
                        onchange={{let value=alias_text.clone();Callback::from(move|text:String|value.set(text))}}/>
                </FormGroup>
            </Form>
        </Modal>
    }
}

/// Page managing the aliases which map stated identifiers to a canonical provider.
#[function_component(ProviderAliasPage)]
pub fn provider_alias_page() -> Html {
    let aliases = use_state(Vec::<ProviderAlias>::new);
    let error = use_state(|| None::<String>);
    let generation = use_state(|| 0u32);
    #[allow(clippy::expect_used)]
    let backdrop = use_backdrop().expect("ProviderAliasPage requires BackdropViewer");
    let latest = use_latest_access_token();
    let token = latest.as_ref().and_then(|t| t.access_token());
    {
        let aliases = aliases.clone();
        let error = error.clone();
        let token = token.clone();
        use_effect_with(*generation, move |_| {
            spawn_local(async move {
                match api::provider_aliases(token.as_deref()).await {
                    Ok(v) => aliases.set(v),
                    Err(e) => error.set(Some(e.to_string())),
                }
            })
        });
    }
    let open = {
        let generation = generation.clone();
        let error = error.clone();
        Callback::from(move |alias: Option<ProviderAlias>| {
            let generation = generation.clone();
            let error = error.clone();
            let on_saved = Callback::from(move |()| {
                error.set(None);
                generation.set(generation.wrapping_add(1));
            });
            backdrop.open(Backdrop::new(html! {
                <Bullseye><AliasDialog {alias} {on_saved}/></Bullseye>
            }));
        })
    };
    let delete = {
        let token = token.clone();
        let generation = generation.clone();
        let error = error.clone();
        Callback::from(move |id: Uuid| {
            let token = token.clone();
            let generation = generation.clone();
            let error = error.clone();
            spawn_local(async move {
                match api::delete_weight_setting("provider-alias", id, token.as_deref()).await {
                    Ok(()) => {
                        error.set(None);
                        generation.set(generation.wrapping_add(1))
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            })
        })
    };
    let edit = {
        let open = open.clone();
        Callback::from(move |alias: ProviderAlias| open.emit(Some(alias)))
    };
    let add = Callback::from(move |_: MouseEvent| open.emit(None));
    html! {
        <PageSection><Stack gutter=true>
            <Title level={Level::H2}>{"Provider aliases"}</Title>
            <p>{"Map the identifiers stated in SBOMs and advisories to a canonical provider. Verdict weighting prefers assertions from the same provider as the SBOM component. Exact identifiers only: name:Acme, namespace:https://acme.example, cve-org:UUID, purl:rpm/acme, distro:acme, cpe-vendor:acme."}</p>
            if let Some(e)=&*error {<Alert title="Settings error" r#type={AlertType::Danger} inline=true><p>{e}</p></Alert>}
            <div><Button variant={ButtonVariant::Primary} onclick={add}>{"Add provider alias"}</Button></div>
            <ProviderAliasTable aliases={(*aliases).clone()} on_edit={edit} on_delete={delete}/>
        </Stack></PageSection>
    }
}
