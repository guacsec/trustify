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

/// Page managing the aliases which map stated identifiers to a canonical provider.
#[function_component(ProviderAliasPage)]
pub fn provider_alias_page() -> Html {
    let aliases = use_state(Vec::<ProviderAlias>::new);
    let error = use_state(|| None::<String>);
    let generation = use_state(|| 0u32);
    let alias_id = use_state(|| None::<Uuid>);
    let provider = use_state(String::new);
    let alias_text = use_state(String::new);
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
    let save = {
        let provider = provider.clone();
        let alias_text = alias_text.clone();
        let alias_id = alias_id.clone();
        let token = token.clone();
        let generation = generation.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            let data = ProviderAliasData {
                provider: (*provider).clone(),
                aliases: alias_text
                    .lines()
                    .filter(|v| !v.trim().is_empty())
                    .map(str::to_string)
                    .collect(),
            };
            let id = *alias_id;
            let token = token.clone();
            let generation = generation.clone();
            let error = error.clone();
            let alias_id = alias_id.clone();
            spawn_local(async move {
                match api::save_provider_alias(id, &data, token.as_deref()).await {
                    Ok(()) => {
                        error.set(None);
                        alias_id.set(None);
                        generation.set(generation.wrapping_add(1))
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            })
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
        let alias_id = alias_id.clone();
        let provider = provider.clone();
        let alias_text = alias_text.clone();
        Callback::from(move |a: ProviderAlias| {
            alias_id.set(Some(a.id));
            provider.set(a.data.provider);
            alias_text.set(a.data.aliases.join("\n"));
        })
    };
    let new_alias = {
        let alias_id = alias_id.clone();
        let provider = provider.clone();
        let alias_text = alias_text.clone();
        Callback::from(move |_: MouseEvent| {
            alias_id.set(None);
            provider.set(String::new());
            alias_text.set(String::new());
        })
    };
    html! {
        <PageSection><Stack gutter=true>
            <Title level={Level::H2}>{"Provider aliases"}</Title>
            <p>{"Map the identifiers stated in SBOMs and advisories to a canonical provider. Verdict weighting prefers assertions from the same provider as the SBOM component. Exact identifiers only: name:Acme, namespace:https://acme.example, cve-org:UUID, purl:rpm/acme, distro:acme, cpe-vendor:acme."}</p>
            if let Some(e)=&*error {<Alert title="Settings error" r#type={AlertType::Danger} inline=true><p>{e}</p></Alert>}
            <ProviderAliasTable aliases={(*aliases).clone()} on_edit={edit} on_delete={delete}/>
            <Card><CardBody><Form limit_width=true onsubmit={Callback::from(|event: SubmitEvent| event.prevent_default())}>
                <Title level={Level::H3}>{if alias_id.is_some(){"Edit provider aliases"}else{"Create provider aliases"}}</Title>
                <Button variant={ButtonVariant::Link} onclick={new_alias}>{"New provider aliases"}</Button>
                {text_field("Canonical provider",provider)}
                <FormGroup label="Aliases (one per line)">
                    <TextArea value={(*alias_text).clone()} rows={4} resize={ResizeOrientation::Vertical}
                        onchange={{let value=alias_text.clone();Callback::from(move|text:String|value.set(text))}}/>
                </FormGroup>
                <ActionGroup><Button onclick={save}>{"Save provider aliases"}</Button></ActionGroup>
            </Form></CardBody></Card>
        </Stack></PageSection>
    }
}
