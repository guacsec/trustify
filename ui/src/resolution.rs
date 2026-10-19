//! Verdict explanations and read-only context previews.
use crate::{AppRoute, api};
use patternfly_yew::prelude::*;
use trustify_api::correlation::*;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Properties, PartialEq)]
pub struct ExplanationProps {
    pub summary: ResolutionSummary,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EvidenceColumn {
    Statement,
    Product,
    Confidence,
    Relationship,
    Origin,
    Role,
}

#[derive(Clone, PartialEq)]
struct EvidenceEntry {
    evidence: ResolutionEvidence,
}

fn provider_name(provider: &ProviderResolution) -> String {
    provider
        .identifiers
        .iter()
        .find_map(|id| id.strip_prefix("name:").map(str::to_owned))
        .or_else(|| provider.provider.clone())
        .unwrap_or_else(|| {
            if provider.diagnostics.is_empty() {
                "Providerless advisory".into()
            } else {
                "Unidentified provider".into()
            }
        })
}

/// Renders a resolved provider, flagging stated identifiers that did not resolve to one.
pub fn provider_view(provider: &ProviderResolution) -> Html {
    let name = provider
        .identifiers
        .iter()
        .find_map(|id| id.strip_prefix("name:"));
    match (&provider.provider, name) {
        (Some(resolved), Some(name)) => html! {
            <>
                { name }
                <div class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">
                    <code style="color: inherit; overflow-wrap: anywhere;">{ resolved }</code>
                </div>
            </>
        },
        (Some(resolved), None) => {
            html!(<code style="overflow-wrap: anywhere;">{ resolved }</code>)
        }
        (None, _) if provider.identifiers.is_empty() && provider.diagnostics.is_empty() => {
            html!(<span class="pf-v6-u-text-color-subtle">{ "None stated" }</span>)
        }
        // Nothing was stated that an alias could map, so only the diagnostics can help.
        (None, _) if provider.identifiers.is_empty() => html! {
            <Tooltip text={provider.diagnostics.join(" ")}>
                <span class="pf-v6-u-text-color-subtle">{ "Unknown" }</span>
            </Tooltip>
        },
        // A stated name still matches the same name on the other side, just unverified.
        (None, Some(name)) => html! {
            <Tooltip text="Identified by its stated name only. Assertions stating the same name count as an unverified match. Add the name to a provider alias to verify it.">
                <span>
                    { name }{ " " }
                    <Link<AppRoute> to={AppRoute::ProviderAliases}>
                        <Label compact=true label="name only" color={Color::Blue}/>
                    </Link<AppRoute>>
                </span>
            </Tooltip>
        },
        (None, None) => {
            let stated = provider.identifiers.first().cloned().unwrap_or_default();
            let more = provider.identifiers.len().saturating_sub(1);
            html! {
                <Tooltip text={format!(
                    "{} Stated: {}. Add one of them to a provider alias to resolve it.",
                    provider.diagnostics.join(" "),
                    provider.identifiers.join(", "),
                )}>
                    <span>
                        <code style="overflow-wrap: anywhere;">{ stated }</code>
                        if more > 0 { { format!(" (+{more})") } }
                        { " " }
                        <Link<AppRoute> to={AppRoute::ProviderAliases}>
                            <Label compact=true label="unresolved" color={Color::Orange}/>
                        </Link<AppRoute>>
                    </span>
                </Tooltip>
            }
        }
    }
}

/// The products a statement was matched in, each once. The tooltip names what confirmed them.
pub(crate) fn product_names(contexts: &[EvidenceContext]) -> Html {
    // per product: the identifiers confirming it, or the unconfirmed link
    let mut products = Vec::<(&str, Vec<&str>, Option<&EvidenceContext>)>::new();
    for context in contexts {
        let index = match products.iter().position(|(name, ..)| *name == context.name) {
            Some(index) => index,
            None => {
                products.push((&context.name, Vec::new(), None));
                products.len() - 1
            }
        };
        let (_, confirmed, unconfirmed) = &mut products[index];
        match context.source {
            ContextSource::Unconfirmed => *unconfirmed = Some(context),
            _ => confirmed.push(&context.node_identifier),
        }
    }
    if products.is_empty() {
        return html!("\u{2014}");
    }
    html! {
        <ul style="margin:0;padding-left:1em">
            {for products.into_iter().map(|(name, confirmed, unconfirmed)| {
                let text = match unconfirmed {
                    Some(context) if confirmed.is_empty() => unconfirmed_text(context),
                    _ => format!("Confirmed by {}", confirmed.join(", ")),
                };
                html! {
                    <li>
                        <Tooltip {text}>
                            <span>
                                { name }
                                if confirmed.is_empty() {
                                    { " " }<Label compact=true label="not confirmed" color={Color::Orange}/>
                                }
                            </span>
                        </Tooltip>
                    </li>
                }
            })}
        </ul>
    }
}

/// Why a product a statement is stated in doesn't count as confirmed.
fn unconfirmed_text(context: &EvidenceContext) -> String {
    format!(
        "Not confirmed: the statement is about {}, but neither the component nor anything above it in the SBOM has {}. Its match confidence is reduced ×{:.2}.",
        context.name,
        match context.context_identifier.is_empty() {
            true => "an identifier of it".to_string(),
            false => context.context_identifier.clone(),
        },
        context.confidence,
    )
}

/// The products a statement was matched in, and the component identifier confirming each.
fn evidence_contexts(contexts: &[EvidenceContext]) -> Html {
    if contexts.is_empty() {
        return Html::default();
    }
    html! {
        <>
            <p>{"Matched in product:"}</p>
            <ul class="pf-v6-c-list">
                {for contexts.iter().map(|context| match context.source {
                    ContextSource::Unconfirmed => html! {
                        <li>
                            <strong>{ &context.name }</strong>{ " " }
                            <Label compact=true label="not confirmed" color={Color::Orange}/>
                            <p class="pf-v6-u-text-color-subtle">{ unconfirmed_text(context) }</p>
                        </li>
                    },
                    _ => html! {
                        <li>
                            { &context.name }{ ", confirmed by the " }{ context.source.label() }
                            if context.distance > 1 {
                                { format!(" ({} hops away)", context.distance) }
                            }
                            { " " }<code style="overflow-wrap: anywhere;">{ &context.node_identifier }</code>
                            <span class="pf-v6-u-text-color-subtle">
                                { format!(" (match confidence ×{:.2})", context.confidence) }
                            </span>
                        </li>
                    },
                })}
            </ul>
        </>
    }
}

fn verdict_color(status: VerdictStatus) -> Color {
    match status {
        VerdictStatus::Affected => Color::Red,
        VerdictStatus::Fixed => Color::Green,
        VerdictStatus::NotAffected => Color::Blue,
        VerdictStatus::UnderInvestigation => Color::Orange,
        VerdictStatus::None => Color::Grey,
    }
}

impl TableEntryRenderer<EvidenceColumn> for EvidenceEntry {
    fn render_cell(&self, context: CellContext<'_, EvidenceColumn>) -> Cell {
        let e = &self.evidence;
        match context.column {
            EvidenceColumn::Statement=>html! {
                <Stack>
                    <StackItem><Link<AppRoute> to={AppRoute::Advisory{id:e.advisory_id.to_string()}}>{provider_name(&e.provider)}</Link<AppRoute>></StackItem>
                    <StackItem><span class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">{e.status.label()}</span></StackItem>
                </Stack>
            }.into(),
            EvidenceColumn::Product => product_names(&e.contexts).into(),
            EvidenceColumn::Confidence=>html!{format!("{:.0}%",e.match_confidence*100.0)}.into(),
            EvidenceColumn::Relationship => html!{e.provider_relationship.label()}.into(),
            EvidenceColumn::Origin => html!{e.assertion_origin.to_string()}.into(),
            EvidenceColumn::Role => html!{
                <Tooltip text={e.selection_reason.label()}>
                    {match e.outcome {
                        EvidenceOutcome::Selected => html!{<Label label="Selected" color={Color::Blue}/>},
                        EvidenceOutcome::Conflicting => html!{<Label label="Conflicting" color={Color::Orange}/>},
                        EvidenceOutcome::Supporting => html!{<span>{"Supporting"}</span>},
                        EvidenceOutcome::NonVoting => html!{<span>{"Does not select verdict"}</span>},
                    }}
                </Tooltip>
            }.into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let e = &self.evidence;
        let content = html! {
            <Stack gutter=true>
                <StackItem><p>{e.selection_reason.label()}</p></StackItem>
                if !e.contexts.is_empty() {
                    <StackItem>{evidence_contexts(&e.contexts)}</StackItem>
                }
                if !e.provider.diagnostics.is_empty() || !e.provider.identifiers.is_empty() {
                    <StackItem>
                        <p>{"Provider identifiers:"}</p>
                        {for e.provider.diagnostics.iter().map(|d|html!{<p class="pf-v6-u-text-color-subtle">{d}</p>})}
                        <ul class="pf-v6-c-list">{for e.provider.identifiers.iter().map(|id|html!{<li><code>{id}</code></li>})}</ul>
                    </StackItem>
                }
            </Stack>
        };
        vec![Span::max(content)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(Explanation)]
fn explanation(props: &ExplanationProps) -> Html {
    let rows = use_memo(props.summary.clone(), |summary| {
        summary
            .explanation
            .as_ref()
            .map(|trace| {
                trace
                    .evidence
                    .iter()
                    .map(|evidence| EvidenceEntry {
                        evidence: evidence.clone(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(rows));
    let Some(trace) = &props.summary.explanation else {
        return Html::default();
    };
    let header = html_nested! {
        <TableHeader<EvidenceColumn>>
            <TableColumn<EvidenceColumn> label="Statement" index={EvidenceColumn::Statement}/>
            <TableColumn<EvidenceColumn> label="Product" index={EvidenceColumn::Product}/>
            <TableColumn<EvidenceColumn> label="Provider relationship" index={EvidenceColumn::Relationship}/>
            <TableColumn<EvidenceColumn> label="Origin" index={EvidenceColumn::Origin}/>
            <TableColumn<EvidenceColumn> label="Match confidence" index={EvidenceColumn::Confidence}/>
            <TableColumn<EvidenceColumn> label="Role" index={EvidenceColumn::Role}/>
        </TableHeader<EvidenceColumn>>
    };
    html! {
        <Stack gutter=true>
            <StackItem>
                <Label label={trace.status.label()} color={verdict_color(trace.status)}/>
                <p>{&trace.reason}</p>
                <p>{format!("Selected match confidence: {:.0}%", props.summary.confidence * 100.0)}</p>
                if props.summary.has_conflict {
                    <Alert title="Conflicting evidence" r#type={AlertType::Warning} inline=true>
                        <p>{"Other applicable statements give a different status. Match confidence describes the selected match; it does not resolve this disagreement."}</p>
                    </Alert>
                }
            </StackItem>
            <StackItem>
                <Title level={Level::H4}>{"Component provider"}</Title>
                {provider_view(&trace.component_provider)}
                <p class="pf-v6-u-text-color-subtle">{&trace.component_provider.source}</p>
                {for trace.component_provider.diagnostics.iter().map(|d|html!{<p>{d}</p>})}
            </StackItem>
            <StackItem>
                <p>{"Statements are ordered by provider relationship, then directness, match confidence, and status. Expand a statement for the deciding rule, its products and provider identifiers."}</p>
                <Table<EvidenceColumn,UseTableData<EvidenceColumn,MemoizedTableModel<EvidenceEntry>>> {header} {entries} {onexpand} mode={TableMode::CompactExpandable}/>
            </StackItem>
            <StackItem><small class="pf-v6-u-text-color-subtle">{"Calculated from current evidence and provider aliases. Resolution revision: "}{trace.resolution_revision.to_string()}</small></StackItem>
        </Stack>
    }
}

#[derive(Clone, Properties, PartialEq)]
pub struct ResolutionPanelProps {
    pub target: PreviewTarget,
    #[prop_or_default]
    pub node_id: Option<String>,
    #[prop_or_default]
    pub vulnerability_id: Option<String>,
}
#[hook]
fn use_open_resolution(props: &ResolutionPanelProps) -> Callback<()> {
    #[allow(clippy::expect_used)]
    let backdrop = use_backdrop().expect("Explaining a verdict requires BackdropViewer");
    let props = props.clone();
    Callback::from(move |()| {
        backdrop.open(Backdrop::new(html! {
            <Bullseye><ResolutionDialog ..props.clone()/></Bullseye>
        }));
    })
}

/// Menu action opening the "Why this verdict?" dialog.
#[function_component(ResolutionAction)]
pub fn resolution_action(props: &ResolutionPanelProps) -> Html {
    let onclick = use_open_resolution(props);
    html! {<MenuAction {onclick}>{"Explain verdict"}</MenuAction>}
}

/// Icon button opening the "Why this verdict?" dialog.
#[function_component(ResolutionButton)]
pub fn resolution_button(props: &ResolutionPanelProps) -> Html {
    let open = use_open_resolution(props);
    let onclick = Callback::from(move |_: MouseEvent| open.emit(()));
    html! {
        <Tooltip text="Why this verdict?">
            <Button
                variant={ButtonVariant::Plain}
                icon={html!(<i class="fas fa-lightbulb" aria-hidden="true"/>)}
                aria_label="Why this verdict?"
                {onclick}
            />
        </Tooltip>
    }
}

#[function_component(ResolutionDialog)]
fn resolution_dialog(props: &ResolutionPanelProps) -> Html {
    let result = use_state(|| None::<PreviewResult>);
    let error = use_state(|| None::<String>);
    let loading = use_state(|| false);
    let provider = use_state(String::new);
    let context = use_state(String::new);
    let is_preview = use_state(|| false);
    #[allow(clippy::expect_used)]
    let backdrop = use_backdrop().expect("ResolutionDialog requires BackdropViewer");
    let close = Callback::from(move |_: MouseEvent| backdrop.close());
    let latest = use_latest_access_token();
    let token = latest.as_ref().and_then(|t| t.access_token());
    let run = {
        let result = result.clone();
        let error = error.clone();
        let loading = loading.clone();
        let provider = provider.clone();
        let props = props.clone();
        let context = context.clone();
        let token = token.clone();
        let is_preview = is_preview.clone();
        Callback::from(move |preview: bool| {
            let product_context = if preview {
                context
                    .lines()
                    .filter(|v| !v.trim().is_empty())
                    .map(|value| IdentifierRef {
                        kind: if value.trim().starts_with("pkg:") {
                            IdentifierKind::Purl
                        } else {
                            IdentifierKind::Cpe
                        },
                        value: value.trim().into(),
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let request = PreviewRequest {
                target: props.target.clone(),
                resolution: ResolutionRequest {
                    include_explanation: true,
                    node_id: props.node_id.clone(),
                    vulnerability_id: props.vulnerability_id.clone(),
                    component_provider: (preview && !provider.trim().is_empty())
                        .then(|| provider.trim().to_string()),
                    product_context,
                },
            };
            let result = result.clone();
            let error = error.clone();
            let loading = loading.clone();
            let token = token.clone();
            is_preview.set(preview);
            error.set(None);
            result.set(None);
            loading.set(true);
            spawn_local(async move {
                match api::preview(&request, token.as_deref()).await {
                    Ok(v) => {
                        result.set(Some(v));
                        error.set(None)
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
                loading.set(false)
            });
        })
    };
    {
        let run = run.clone();
        // Fetch as soon as the modal opens. Editing context does not alter this request.
        use_effect_with((props.clone(), token), move |_| run.emit(false));
    }
    let summaries = match &*result {
        Some(PreviewResult::Sbom(v)) => v
            .verdicts
            .iter()
            .map(|v| {
                (
                    format!(
                        "{} / {}: {}",
                        v.component.name,
                        v.vulnerability.id,
                        v.status.label()
                    ),
                    v.resolution.clone(),
                )
            })
            .collect::<Vec<_>>(),
        Some(PreviewResult::Identifier(v)) => v
            .verdicts
            .iter()
            .map(|v| {
                (
                    format!("{}: {}", v.vulnerability_id, v.status.label()),
                    v.resolution.clone(),
                )
            })
            .collect(),
        None => Vec::new(),
    };
    let footer =
        html! {<Button variant={ButtonVariant::Secondary} onclick={close}>{"Close"}</Button>};
    let description = match (&props.node_id, &props.vulnerability_id) {
        (Some(node), Some(vulnerability)) => format!("{vulnerability} · component {node}"),
        (_, Some(vulnerability)) => vulnerability.clone(),
        _ => "Current evidence and provider aliases".into(),
    };
    let multiple = summaries.len() > 1;
    html! {<Modal title="Why this verdict?" variant={ModalVariant::Large} {footer}>
        <div class="trustify-verdict-explanation"><Stack gutter=true>
        <StackItem><p class="pf-v6-u-text-color-subtle">{description}</p></StackItem>
        if *loading {<Bullseye><Spinner/></Bullseye>}
        if let Some(e)=&*error {<Alert title="Unable to resolve" r#type={AlertType::Danger} inline=true><p>{e}</p></Alert>}
        if result.is_some() && summaries.is_empty() {
            <Alert title="No verdict found" r#type={AlertType::Info} inline=true>
                <p>{"No applicable verdict was returned for this component and vulnerability. Refresh the correlation result to check the current evidence."}</p>
            </Alert>
        }
        {for summaries.into_iter().map(|(label,summary)|html!{
            <div>
                if *is_preview {<Title level={Level::H4}>{"Temporary preview"}</Title>}
                if multiple {<Title level={Level::H4}>{label}</Title>}
                if summary.explanation.is_some() {<Explanation {summary}/>}
                else {<Alert title="Explanation unavailable" r#type={AlertType::Warning} inline=true><p>{"The server returned a verdict without its explanation."}</p></Alert>}
            </div>
        })}
        <details><summary>{"Try temporary context"}</summary><p>{"Preview uses a temporary component provider or product context without saving changes."}</p>
            <Form limit_width=true onsubmit={Callback::from(|event: SubmitEvent| event.prevent_default())}>
            {text_field("Component provider (optional)",provider)}
            if matches!(props.target,PreviewTarget::Identifier{..}) {
                <FormGroup label="Product context CPEs or RPM PURLs (one per line, optional)">
                    <TextArea value={(*context).clone()} rows={3} resize={ResizeOrientation::Vertical}
                        onchange={{let value=context.clone();Callback::from(move|text:String|value.set(text))}}/>
                </FormGroup>
            }
            <ActionGroup>
                <Button variant={ButtonVariant::Primary} onclick={run.reform(|_:MouseEvent|true)} disabled={*loading}>{"Preview context"}</Button>
                <Button variant={ButtonVariant::Link} onclick={run.reform(|_:MouseEvent|false)} disabled={*loading}>{"Show current verdict"}</Button>
            </ActionGroup>
            </Form>
        </details>
        </Stack></div>
    </Modal>}
}

pub(crate) fn text_field(label: &'static str, value: UseStateHandle<String>) -> Html {
    let onchange = {
        let value = value.clone();
        Callback::from(move |text: String| value.set(text))
    };
    html! {
        <FormGroup label={label}>
            <TextInput value={(*value).clone()} {onchange}/>
        </FormGroup>
    }
}
