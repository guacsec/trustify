//! Verdict explanations and read-only context previews.
use crate::{AppRoute, api, correlation::status_color};
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

/// A match confidence as the product of its factors below 100%, e.g. `70% × 70% = 49%`. `None`
/// for evidence without recorded factors.
fn factors_formula(factors: &[ConfidenceFactor], confidence: f64) -> Option<String> {
    if factors.is_empty() {
        return None;
    }
    let reducing = factors
        .iter()
        .filter(|f| f.factor < 1.0)
        .map(|f| percent(f.factor))
        .collect::<Vec<_>>();
    Some(match reducing.as_slice() {
        [] => format!("{} (nothing reduces it)", percent(confidence)),
        [single] => single.clone(),
        many => format!("{} = {}", many.join(" × "), percent(confidence)),
    })
}

pub(crate) fn percent(value: f64) -> String {
    format!("{:.0}%", value * 100.0)
}

/// Why a factor applies to a match confidence.
pub(crate) fn factor_text(factor: &ConfidenceFactor, contexts: &[EvidenceContext]) -> String {
    match &factor.reason {
        ConfidenceReason::Digest => "The file digest is equal.".into(),
        ConfidenceReason::ProductIdentifier => {
            "A product identifier (SKU, model or serial number) matches.".into()
        }
        ConfidenceReason::CpeExactVersion => {
            "The advisory's CPE states the component's version.".into()
        }
        ConfidenceReason::CpeVersionRange => "The advisory's CPE has no version, the component's version is in the version range of the statement.".into(),
        ConfidenceReason::CpeAnyVersion => {
            "The advisory's CPE applies to all versions, without a version range.".into()
        }
        ConfidenceReason::Purl => "The PURL is in a version range the advisory states.".into(),
        ConfidenceReason::RpmStream { stream } => match stream {
            StreamRelation::Exact => "The RPM's release stream (e.g. el8_6) is the statement's.",
            StreamRelation::Major => "The RPM's release stream only shares its major version with the statement's (e.g. el8 and el8_6).",
            StreamRelation::Minor => "The statement is about another minor stream of the same major version (e.g. el9_0 and el9_1), and nothing is stated for the RPM's own.",
        }
        .into(),
        ConfidenceReason::Rule { rule } => rule_text(rule),
        ConfidenceReason::DefaultStatus => {
            "The status is the advisory's default for versions it doesn't list.".into()
        }
        ConfidenceReason::ProductConfirmed {
            source,
            distance,
            source_factor,
            wildcard_factor,
        } => {
            let mut text = format!(
                "The product identified by the {}{} matches the product named in the advisory.",
                source.label(),
                match distance {
                    0 | 1 => String::new(),
                    hops => format!(" ({hops} hops away)"),
                }
            );
            match (source_factor, wildcard_factor) {
                (Some(source_factor), Some(wildcard_factor)) => {
                    text.push_str(&format!(
                        " Source confidence: {}. {}: {}. Product factor: {} × {} = {} (rounded).",
                        percent(*source_factor),
                        if *wildcard_factor < 1.0 {
                            "Wildcard CPE match"
                        } else {
                            "Exact identifier match"
                        },
                        percent(*wildcard_factor),
                        percent(*source_factor),
                        percent(*wildcard_factor),
                        percent(factor.factor),
                    ));
                    if factor.factor < 1.0 {
                        text.push_str(" Product confirmation establishes compatibility; the match method still reduces confidence.");
                    }
                }
                _ => text.push_str(" The source and wildcard breakdown was not recorded for this evidence. Re-extract correlation evidence to record it."),
            }
            text
        }
        ConfidenceReason::ProductNotConfirmed => {
            let names = contexts
                .iter()
                .filter(|c| c.source == ContextSource::Unconfirmed)
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>();
            match names.is_empty() {
                true => "Nothing in the SBOM confirms the product the statement is about.".into(),
                false => format!(
                    "Nothing in the SBOM confirms the product the statement is about: {}.",
                    names.join(", ")
                ),
            }
        }
    }
}

/// Why a rule derived the range of a statement, by its evidence type.
pub(crate) fn rule_text(rule: &str) -> String {
    match rule {
        "purl_first_fixed" => "The advisory states the first fixed version: it and later versions are fixed.",
        "purl_first_fixed_before" => "The advisory states the first fixed version: earlier versions are affected.",
        "purl_fixed_as_first_fixed" => "The publisher's fixed version is read as the first fixed one: later builds of the stream are fixed.",
        "purl_fixed_as_first_fixed_before" => "The publisher's fixed version is read as the first fixed one: earlier builds of the stream are affected.",
        "purl_first_affected" => "The advisory states the first affected version.",
        "purl_last_affected" => "The advisory states the last affected version.",
        "purl_any_version" => "The publisher's PURL without a version is read as all versions.",
        "purl_vls_range" => "The version range states no versioning scheme, it is compared with the one of the PURL type.",
        "purl_custom_range" => "The CVE range has a custom version type, it is compared with the scheme of the PURL type.",
        "purl_suse_recommended" => "SUSE's recommended version is read as the fix: it and later builds are fixed.",
        "purl_suse_recommended_before" => "SUSE's recommended version is read as the fix: earlier builds are affected.",
        other => return format!("The rule {other} derived the version range."),
    }
    .into()
}

/// A short name of the reason of a factor.
pub(crate) fn factor_label(factor: &ConfidenceFactor) -> &'static str {
    match &factor.reason {
        ConfidenceReason::Digest => "File digest",
        ConfidenceReason::ProductIdentifier => "Product identifier",
        ConfidenceReason::CpeExactVersion => "CPE with the exact version",
        ConfidenceReason::CpeVersionRange => "CPE version in range",
        ConfidenceReason::CpeAnyVersion => "CPE for all versions",
        ConfidenceReason::Purl => "PURL version in range",
        ConfidenceReason::RpmStream { stream } => match stream {
            StreamRelation::Exact => "Same RPM stream",
            StreamRelation::Major => "RPM stream shares the major only",
            StreamRelation::Minor => "Other minor RPM stream",
        },
        ConfidenceReason::Rule { .. } => "Range derived by a rule",
        ConfidenceReason::DefaultStatus => "Default status",
        ConfidenceReason::ProductConfirmed { .. } => "Product match",
        ConfidenceReason::ProductNotConfirmed => "Product not confirmed",
    }
}

/// How a match confidence comes about: each factor with its reason, and the result.
pub(crate) fn confidence_breakdown(
    factors: &[ConfidenceFactor],
    contexts: &[EvidenceContext],
    confidence: f64,
) -> Html {
    html! {
        <Stack>
            <StackItem>
                <ul class="pf-v6-c-list pf-m-plain">
                    {for factors.iter().enumerate().map(|(index, f)| html! {
                        <li>
                            <strong>{ if index == 0 { "" } else { "× " } }{ percent(f.factor) }</strong>
                            { " " }{ factor_label(f) }
                            <div class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">
                                { factor_text(f, contexts) }
                            </div>
                        </li>
                    })}
                </ul>
            </StackItem>
            <StackItem>
                <strong>{ format!("= {} match confidence", percent(confidence)) }</strong>
                <p class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">
                    { "These percentages are matching heuristics, not the probability that the component is vulnerable." }
                </p>
                <Link<AppRoute> to={AppRoute::Confidence}>{ "How match confidence works" }</Link<AppRoute>>
            </StackItem>
        </Stack>
    }
}

/// A match confidence, opening a popover with its breakdown if its factors are recorded.
pub(crate) fn confidence_cell(
    factors: &[ConfidenceFactor],
    contexts: &[EvidenceContext],
    confidence: f64,
) -> Html {
    if factors.is_empty() {
        return html!(percent(confidence));
    }
    let target = html! {
        <Button
            variant={ButtonVariant::InlineLink}
            label={percent(confidence)}
            icon={html!(<i class="fas fa-circle-info" aria-hidden="true"/>)}
            align={Align::End}
            style="white-space: nowrap;"
        />
    };
    html! {
        <Popover {target} body={html_nested! {
            <PopoverBody header={html!("How the match confidence comes about")}>
                { confidence_breakdown(factors, contexts, confidence) }
            </PopoverBody>
        }}/>
    }
}

/// How the match confidence of a statement comes about, in its details.
fn confidence_factors(e: &ResolutionEvidence) -> Html {
    let Some(formula) = factors_formula(&e.confidence_factors, e.match_confidence) else {
        return Html::default();
    };
    html! {
        <>
            <p>{ format!("Match confidence: {formula}") }</p>
            { confidence_breakdown(&e.confidence_factors, &e.contexts, e.match_confidence) }
        </>
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
            EvidenceColumn::Confidence => {
                confidence_cell(&e.confidence_factors, &e.contexts, e.match_confidence).into()
            }
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
                if !e.confidence_factors.is_empty() {
                    <StackItem>{confidence_factors(e)}</StackItem>
                }
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
                <Label label={trace.status.label()} color={status_color(trace.status)}/>
                <p>{&trace.reason}</p>
                <p>{format!("Confidence:\u{a0}{:.0}%", props.summary.confidence * 100.0)}</p>
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
                <p>{"Statements are ordered by provider relationship, then directness, match confidence, and status. Expand a statement for the deciding rule, how its match confidence comes about, its products and provider identifiers."}</p>
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn confirmed_product_explains_discounts() {
        let product = ConfidenceFactor::new(
            ConfidenceReason::ProductConfirmed {
                source: ContextSource::PurlQualifier,
                distance: 0,
                source_factor: Some(0.85),
                wildcard_factor: Some(0.9),
            },
            0.77,
        );
        let text = factor_text(&product, &[]);
        assert!(text.contains("Source confidence: 85%"));
        assert!(text.contains("Wildcard CPE match: 90%"));
        assert!(text.contains("85% × 90% = 77% (rounded)"));
        let factors = [
            ConfidenceFactor::new(
                ConfidenceReason::Rule {
                    rule: "purl_fixed_as_first_fixed_before".into(),
                },
                0.9,
            ),
            product,
        ];
        assert_eq!(
            factors_formula(&factors, combine(&factors)).as_deref(),
            Some("90% × 77% = 69%")
        );
    }

    #[test]
    fn exact_product_match_has_no_discount() {
        let factor = ConfidenceFactor::new(
            ConfidenceReason::ProductConfirmed {
                source: ContextSource::Node,
                distance: 0,
                source_factor: Some(1.0),
                wildcard_factor: Some(1.0),
            },
            1.0,
        );
        let text = factor_text(&factor, &[]);
        assert!(text.contains("Exact identifier match: 100%"));
        assert!(!text.contains("still reduces confidence"));
    }

    #[test]
    fn older_product_evidence_does_not_invent_discounts() {
        let factor: ConfidenceFactor = serde_json::from_str(
            r#"{"reason":{"kind":"product_confirmed","source":"purl_qualifier","distance":0},"factor":0.77}"#,
        ).unwrap();
        let text = factor_text(&factor, &[]);
        assert!(text.contains("breakdown was not recorded"));
        assert!(!text.contains("85%"));
    }
}
