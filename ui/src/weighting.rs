//! Verdict policy settings and read-only explanations/previews.
use crate::{AppRoute, api};
use patternfly_yew::prelude::*;
use trustify_api::correlation::*;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Properties, PartialEq)]
pub struct WeightEditorProps {
    pub value: WeightOverrides,
    pub onchange: Callback<Result<WeightOverrides, String>>,
}

/// Empty controls inherit their value. Map controls accept one key=multiplier per line.
#[function_component(WeightEditor)]
fn weight_editor(props: &WeightEditorProps) -> Html {
    let drafts = use_state(|| weight_drafts(&props.value));
    let last_value = use_mut_ref(|| props.value.clone());
    {
        let drafts = drafts.clone();
        let last_value = last_value.clone();
        use_effect_with(props.value.clone(), move |value| {
            if *last_value.borrow() != *value {
                drafts.set(weight_drafts(value));
                *last_value.borrow_mut() = value.clone();
            }
        });
    }
    let onfield = {
        let drafts = drafts.clone();
        let last_value = last_value.clone();
        let onchange = props.onchange.clone();
        Callback::from(move |(key, value): (&'static str, String)| {
            let mut next = (*drafts).clone();
            next.insert(key.into(), value);
            let parsed = parse_weights(&next);
            if let Ok(value) = &parsed {
                *last_value.borrow_mut() = value.clone();
            }
            drafts.set(next);
            onchange.emit(parsed);
        })
    };
    let fields = [
        ("matching_provider", "Matching provider", "2"),
        (
            "matching_provider_name",
            "Same provider name (unverified)",
            "1.5",
        ),
        ("providerless", "Generic alongside matching provider", "1"),
        ("providerless_fallback", "Generic fallback", "2"),
        ("other_provider", "Other or unidentified provider", "0.5"),
        ("direct", "Direct statement or default", "1.25"),
        ("inferred", "Inferred statement", "1"),
        (
            "conflict_sensitivity",
            "Conflict sensitivity (0 to below 1)",
            "0.5",
        ),
        ("component_provider", "Component provider", "Inherited"),
    ];
    html! {
        <FormSection title={Some("Weights".to_string())}>
            <p>{"Leave a field empty to inherit. Independent multipliers multiply; a more specific setting replaces the same inherited setting."}</p>
            {for fields.into_iter().map(|(key,label,default)| {
                let current = drafts.get(key).cloned().unwrap_or_default();
                let onfield = onfield.clone();
                let onchange = Callback::from(move |value: String| {
                    onfield.emit((key,value));
                });
                html!{
                    <FormGroup label={label}>
                        <TextInput value={current} placeholder={format!("Inherited (default {default})")} {onchange}/>
                    </FormGroup>
                }
            })}
            {for [("providers","Provider multipliers"),("match_methods","Match method multipliers"),("rules","Rule multipliers")].into_iter().map(|(key,label)| {
                let current = drafts.get(key).cloned().unwrap_or_default();
                let onfield = onfield.clone();
                let onchange=Callback::from(move |value: String| {
                    onfield.emit((key,value));
                });
                html!{
                    <FormGroup label={label}>
                        <TextArea value={current} placeholder="key=multiplier, one per line" rows={3} resize={ResizeOrientation::Vertical} {onchange}/>
                    </FormGroup>
                }
            })}
        </FormSection>
    }
}

fn weight_drafts(weights: &WeightOverrides) -> std::collections::BTreeMap<String, String> {
    serde_json::to_value(weights)
        .unwrap_or_default()
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, value)| {
            let text = if let Some(map) = value.as_object() {
                map.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else if let Some(v) = value.as_str() {
                v.into()
            } else if value.is_null() {
                String::new()
            } else {
                value.to_string()
            };
            (key.clone(), text)
        })
        .collect()
}

fn parse_weights(
    drafts: &std::collections::BTreeMap<String, String>,
) -> Result<WeightOverrides, String> {
    let number = |key: &str, text: &str| -> Result<f64, String> {
        let value = text
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("{key} must be a number"))?;
        if !value.is_finite() || value < 0.0 || (key == "conflict_sensitivity" && value >= 1.0) {
            return Err(format!(
                "{key} must be finite and nonnegative; sensitivity must be below 1"
            ));
        }
        Ok(value)
    };
    let mut result = serde_json::Map::new();
    for (key, text) in drafts {
        let value = if ["providers", "match_methods", "rules"].contains(&key.as_str()) {
            let mut map = serde_json::Map::new();
            for line in text.lines().filter(|v| !v.trim().is_empty()) {
                let (entry, value) = line
                    .rsplit_once('=')
                    .ok_or_else(|| format!("{key}: use key=multiplier, one per line"))?;
                let entry = entry.trim();
                if entry.is_empty() || map.contains_key(entry) {
                    return Err(format!("{key}: keys must be nonempty and unique"));
                }
                map.insert(entry.into(), serde_json::json!(number(key, value)?));
            }
            serde_json::Value::Object(map)
        } else if text.trim().is_empty() {
            serde_json::Value::Null
        } else if key == "component_provider" {
            serde_json::json!(text.trim())
        } else {
            serde_json::json!(number(key, text)?)
        };
        result.insert(key.clone(), value);
    }
    serde_json::from_value(serde_json::Value::Object(result)).map_err(|e| e.to_string())
}

#[derive(Clone, Properties, PartialEq)]
pub struct ExplanationProps {
    pub summary: ResolutionSummary,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WeightColumn {
    Statement,
    Confidence,
    Weight,
    Role,
}

#[derive(Clone, PartialEq)]
struct WeightEntry {
    evidence: EvidenceWeight,
    winning: bool,
    opposing: bool,
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

fn verdict_color(status: VerdictStatus) -> Color {
    match status {
        VerdictStatus::Affected => Color::Red,
        VerdictStatus::Fixed => Color::Green,
        VerdictStatus::NotAffected => Color::Blue,
        VerdictStatus::UnderInvestigation => Color::Orange,
        VerdictStatus::None => Color::Grey,
    }
}

impl TableEntryRenderer<WeightColumn> for WeightEntry {
    fn render_cell(&self, context: CellContext<'_, WeightColumn>) -> Cell {
        let e = &self.evidence;
        match context.column {
            WeightColumn::Statement=>html! {
                <Stack>
                    <StackItem><Link<AppRoute> to={AppRoute::Advisory{id:e.advisory_id.to_string()}}>{provider_name(&e.provider)}</Link<AppRoute>></StackItem>
                    <StackItem><span class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">{e.status.label()}</span></StackItem>
                </Stack>
            }.into(),
            WeightColumn::Confidence=>html!{format!("{:.0}%",e.match_confidence*100.0)}.into(),
            WeightColumn::Weight=>html!{<strong>{format!("{:.3}",e.weight)}</strong>}.into(),
            WeightColumn::Role=>html!{
                if self.winning {<Label label="Winner" color={Color::Blue}/>}
                else if self.opposing {<Label label="Opposition" color={Color::Orange}/>}
                else {<span class="pf-v6-u-text-color-subtle">{"Other evidence"}</span>}
            }.into(),
        }
    }
}

fn factor_label(key: &str) -> String {
    match key {
        "matching_provider" => "Matching provider".into(),
        "matching_provider_name" => "Same provider name (unverified)".into(),
        "providerless" => "Generic alongside matching provider".into(),
        "providerless_fallback" => "Generic fallback".into(),
        "other_provider" => "Other or unidentified provider".into(),
        "direct" => "Direct statement".into(),
        "inferred" => "Inferred statement".into(),
        "conflict_sensitivity" => "Conflict sensitivity".into(),
        "component_provider" => "Component provider".into(),
        _ => {
            if let Some(provider) = key.strip_prefix("providers.") {
                format!("Provider preference: {provider}")
            } else if let Some(method) = key.strip_prefix("match_methods.") {
                format!("Match method: {method}")
            } else if let Some(rule) = key.strip_prefix("rules.") {
                format!("Rule: {rule}")
            } else {
                key.into()
            }
        }
    }
}

#[function_component(Explanation)]
fn explanation(props: &ExplanationProps) -> Html {
    let rows = use_memo(props.summary.clone(), |summary| {
        let Some(trace) = &summary.explanation else {
            return Vec::new();
        };
        let mut rows = trace
            .evidence
            .iter()
            .map(|e| WeightEntry {
                evidence: e.clone(),
                winning: trace.winning_evidence.as_ref() == Some(&e.evidence_ref),
                opposing: trace.opposing_evidence.as_ref() == Some(&e.evidence_ref),
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            b.evidence
                .weight
                .total_cmp(&a.evidence.weight)
                .then(b.winning.cmp(&a.winning))
                .then(a.evidence.evidence_ref.cmp(&b.evidence.evidence_ref))
        });
        rows
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(rows));
    let Some(trace) = &props.summary.explanation else {
        return Html::default();
    };
    let status = trace
        .statuses
        .first()
        .map(|s| s.status)
        .unwrap_or(VerdictStatus::None);
    let header = html_nested! {
        <TableHeader<WeightColumn>>
            <TableColumn<WeightColumn> label="Statement" index={WeightColumn::Statement}/>
            <TableColumn<WeightColumn> label="Match confidence" index={WeightColumn::Confidence}/>
            <TableColumn<WeightColumn> label="Weight" index={WeightColumn::Weight}/>
            <TableColumn<WeightColumn> label="Role" index={WeightColumn::Role}/>
        </TableHeader<WeightColumn>>
    };
    html! {
        <Stack gutter=true>
            <StackItem><Card><CardBody>
                <Stack gutter=true>
                    <StackItem><Flex space_items={[SpaceItems::Small]}>
                        <FlexItem><Label label={status.label()} color={verdict_color(status)}/></FlexItem>
                        <FlexItem><strong>{format!("{:.0}% confidence",props.summary.confidence*100.0)}</strong></FlexItem>
                        <FlexItem>if props.summary.has_conflict {<Label label="Conflicting statements" color={Color::Orange}/>}</FlexItem>
                    </Flex></StackItem>
                    <StackItem><p>{if status==VerdictStatus::None {trace.reason.clone()}else if trace.tie_break {
                        format!("The strongest statements have equal weights ({:.3}). The status tie-break rule selects {}.",props.summary.decision_weight,status.label())
                    }else{
                        format!("The strongest {} statement has the highest decision weight ({:.3}).",status.label(),props.summary.decision_weight)
                    }}</p></StackItem>
                    if props.summary.has_conflict {<StackItem><p class="pf-v6-u-text-color-subtle">
                        {format!("Opposing evidence reduces confidence from {:.0}% to {:.0}%.",trace.base_confidence*100.0,props.summary.confidence*100.0)}
                    </p></StackItem>}
                </Stack>
            </CardBody></Card></StackItem>
            <StackItem>
                <Title level={Level::H3}>{"Component provider"}</Title>
                <p>{provider_name(&trace.component_provider)}<span class="pf-v6-u-text-color-subtle">{format!(" · {}",trace.component_provider.source)}</span></p>
                {for trace.component_provider.diagnostics.iter().map(|d|html!{<p class="pf-v6-u-text-color-subtle">{d}</p>})}
            </StackItem>
            <StackItem>
                <Title level={Level::H3}>{"Evidence comparison"}</Title>
                <p class="pf-v6-u-text-color-subtle">{"The strongest statement for each status decides. Repeated statements do not add votes."}</p>
                <div class="trustify-verdict-table">
                    <Table<WeightColumn,UseTableData<WeightColumn,MemoizedTableModel<WeightEntry>>> {header} {entries} mode={TableMode::Compact}/>
                </div>
            </StackItem>
            <StackItem><details>
                <summary>{"Weight factors and sources"}</summary>
                <Stack gutter=true>{for trace.evidence.iter().map(|e|html!{<StackItem>
                    <strong>{format!("{} · {}",provider_name(&e.provider),e.status.label())}</strong>
                    <p class="pf-v6-u-text-color-subtle">{format!("Origin: {}. Match confidence: {:.0}%.",e.assertion_origin,e.match_confidence*100.0)}</p>
                    <ul class="pf-v6-c-list">{for e.factors.iter().map(|f|html!{<li>
                        {format!("{} × {}",factor_label(&f.factor),f.multiplier)}
                        <span class="pf-v6-u-text-color-subtle">{format!(" — {}",setting_source(&f.origin))}</span>
                    </li>})}</ul>
                    {for e.provider.diagnostics.iter().map(|d|html!{<p>{d}</p>})}
                    <details><summary>{"Source identifiers"}</summary><ul class="pf-v6-c-list">{for e.provider.identifiers.iter().map(|id|html!{<li><code>{id}</code></li>})}</ul></details>
                </StackItem>})}</Stack>
            </details></StackItem>
            <StackItem><details>
                <summary>{"Confidence calculation and policy"}</summary>
                <p>{format!("Confidence = {:.3} × (1 − {:.3}) = {:.3}.",trace.base_confidence,if trace.base_confidence>0.0 {trace.confidence_penalty/trace.base_confidence}else{0.0},props.summary.confidence)}</p>
                <p>{format!("Strongest opposing weight: {:.3}.",trace.opposing_weight)}</p>
                <p>{"Policy revision: "}<code>{trace.policy_revision.to_string()}</code></p>
                <ul class="pf-v6-c-list">{for trace.settings.iter().map(|(key,s)|html!{<li>
                    {format!("{}: {}",factor_label(key),s.value)}
                    <span class="pf-v6-u-text-color-subtle">{format!(" — {}",setting_source(&s.origin))}</span>
                    if let Some(id)=s.origin.policy_id {<details><summary>{"Policy reference"}</summary>
                        <p><code>{id.to_string()}</code></p>
                        if let Some(revision)=s.origin.revision {<p>{"Revision: "}<code>{revision.to_string()}</code></p>}
                    </details>}
                </li>})}</ul>
            </details></StackItem>
        </Stack>
    }
}

fn setting_source(origin: &SettingOrigin) -> String {
    match &origin.scope {
        Some(PolicyScope::Group { group_id }) => format!("group {group_id}"),
        Some(PolicyScope::Sbom { sbom_id }) => format!("SBOM {sbom_id}"),
        Some(PolicyScope::Component { sbom_id, node_id }) => {
            format!("component {node_id} in SBOM {sbom_id}")
        }
        _ => origin.source.clone(),
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
    let weights = use_state(WeightOverrides::default);
    let valid = use_state(|| true);
    let group = use_state(String::new);
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
        let weights = weights.clone();
        let props = props.clone();
        let group = group.clone();
        let context = context.clone();
        let token = token.clone();
        let is_preview = is_preview.clone();
        Callback::from(move |preview: bool| {
            let group_id = if !preview || group.trim().is_empty() {
                None
            } else {
                match group.trim().parse::<Uuid>() {
                    Ok(id) => Some(id),
                    Err(_) => {
                        error.set(Some("Group ID must be a UUID".into()));
                        return;
                    }
                }
            };
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
                    overrides: if preview {
                        (*weights).clone()
                    } else {
                        WeightOverrides::default()
                    },
                    group_id,
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
        // Fetch as soon as the modal opens. Editing weights does not alter this request.
        use_effect_with((props.clone(), token), move |_| run.emit(false));
    }
    let change = {
        let weights = weights.clone();
        let valid = valid.clone();
        let error = error.clone();
        Callback::from(move |v: Result<WeightOverrides, String>| match v {
            Ok(v) => {
                weights.set(v);
                valid.set(true);
                error.set(None)
            }
            Err(e) => {
                valid.set(false);
                error.set(Some(e))
            }
        })
    };
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
        _ => "Current evidence and weighting policy".into(),
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
        <details><summary>{"Try temporary weights"}</summary><p>{"Preview recalculates current evidence without saving settings. The result below includes the policy revision used."}</p>
            <Form limit_width=true onsubmit={Callback::from(|event: SubmitEvent| event.prevent_default())}>
            if matches!(props.target,PreviewTarget::Sbom{..}) {
                {text_field("Select assigned group UUID (optional)",group)}
            }
            if matches!(props.target,PreviewTarget::Identifier{..}) {
                <FormGroup label="Product context CPEs or RPM PURLs (one per line, optional)">
                    <TextArea value={(*context).clone()} rows={3} resize={ResizeOrientation::Vertical}
                        onchange={{let value=context.clone();Callback::from(move|text:String|value.set(text))}}/>
                </FormGroup>
            }
            <WeightEditor value={(*weights).clone()} onchange={change}/>
            <ActionGroup>
                <Button variant={ButtonVariant::Primary} onclick={run.reform(|_:MouseEvent|true)} disabled={*loading || !*valid}>{"Preview weights"}</Button>
                <Button variant={ButtonVariant::Link} onclick={run.reform(|_:MouseEvent|false)} disabled={*loading}>{"Show current verdict"}</Button>
            </ActionGroup>
            </Form>
        </details>
        </Stack></div>
    </Modal>}
}

#[function_component(WeightingPage)]
pub fn weighting_page() -> Html {
    let policies = use_state(Vec::<WeightPolicy>::new);
    let error = use_state(|| None::<String>);
    let generation = use_state(|| 0u32);
    let policy_id = use_state(|| None::<Uuid>);
    let editor_generation = use_state(|| 0u32);
    let scope = use_state(|| "instance".to_string());
    let scope_id = use_state(String::new);
    let node = use_state(String::new);
    let priority = use_state(|| "0".to_string());
    let weights = use_state(WeightOverrides::default);
    let valid = use_state(|| true);
    let latest = use_latest_access_token();
    let token = latest.as_ref().and_then(|t| t.access_token());
    {
        let policies = policies.clone();
        let error = error.clone();
        let token = token.clone();
        use_effect_with(*generation, move |_| {
            spawn_local(async move {
                match api::weight_policies(token.as_deref()).await {
                    Ok(v) => policies.set(v),
                    Err(e) => error.set(Some(e.to_string())),
                }
            })
        });
    }
    let change = {
        let weights = weights.clone();
        let error = error.clone();
        let valid = valid.clone();
        Callback::from(move |v: Result<WeightOverrides, String>| match v {
            Ok(v) => {
                weights.set(v);
                valid.set(true);
                error.set(None)
            }
            Err(e) => {
                valid.set(false);
                error.set(Some(e))
            }
        })
    };
    let save = {
        let scope = scope.clone();
        let scope_id = scope_id.clone();
        let node = node.clone();
        let priority = priority.clone();
        let weights = weights.clone();
        let policy_id = policy_id.clone();
        let token = token.clone();
        let generation = generation.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            let data = (|| -> Result<WeightPolicyData, String> {
                let id = || {
                    scope_id
                        .parse::<Uuid>()
                        .map_err(|_| "Scope ID must be a UUID".to_string())
                };
                let scope = match scope.as_str() {
                    "instance" => PolicyScope::Instance,
                    "group" => PolicyScope::Group { group_id: id()? },
                    "sbom" => PolicyScope::Sbom { sbom_id: id()? },
                    "component" => PolicyScope::Component {
                        sbom_id: id()?,
                        node_id: (*node).clone(),
                    },
                    _ => return Err("Choose a scope".into()),
                };
                Ok(WeightPolicyData {
                    scope,
                    priority: priority
                        .parse()
                        .map_err(|_| "Priority must be an integer")?,
                    weights: (*weights).clone(),
                })
            })();
            let token = token.clone();
            let generation = generation.clone();
            let error = error.clone();
            let policy_id = policy_id.clone();
            let id = *policy_id;
            match data {
                Err(e) => error.set(Some(e)),
                Ok(data) => spawn_local(async move {
                    match api::save_weight_policy(id, &data, token.as_deref()).await {
                        Ok(()) => {
                            error.set(None);
                            policy_id.set(None);
                            generation.set(generation.wrapping_add(1));
                        }
                        Err(e) => error.set(Some(e.to_string())),
                    }
                }),
            }
        })
    };
    let delete = {
        let token = token.clone();
        let generation = generation.clone();
        let error = error.clone();
        Callback::from(move |(resource, id): (&'static str, Uuid)| {
            let token = token.clone();
            let generation = generation.clone();
            let error = error.clone();
            spawn_local(async move {
                match api::delete_weight_setting(resource, id, token.as_deref()).await {
                    Ok(()) => {
                        error.set(None);
                        generation.set(generation.wrapping_add(1))
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            })
        })
    };
    let edit_policy = {
        let editor_generation = editor_generation.clone();
        let policy_id = policy_id.clone();
        let scope = scope.clone();
        let scope_id = scope_id.clone();
        let node = node.clone();
        let priority = priority.clone();
        let weights = weights.clone();
        let valid = valid.clone();
        let error = error.clone();
        Callback::from(move |p: WeightPolicy| {
            editor_generation.set(editor_generation.wrapping_add(1));
            policy_id.set(Some(p.id));
            scope.set(p.data.scope.to_string());
            match &p.data.scope {
                PolicyScope::Instance => scope_id.set(String::new()),
                PolicyScope::Group { group_id } => scope_id.set(group_id.to_string()),
                PolicyScope::Sbom { sbom_id } => scope_id.set(sbom_id.to_string()),
                PolicyScope::Component { sbom_id, node_id } => {
                    scope_id.set(sbom_id.to_string());
                    node.set(node_id.clone());
                }
            }
            priority.set(p.data.priority.to_string());
            weights.set(p.data.weights);
            valid.set(true);
            error.set(None);
        })
    };
    let new_policy = {
        let editor_generation = editor_generation.clone();
        let policy_id = policy_id.clone();
        let scope = scope.clone();
        let scope_id = scope_id.clone();
        let node = node.clone();
        let priority = priority.clone();
        let weights = weights.clone();
        let valid = valid.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            editor_generation.set(editor_generation.wrapping_add(1));
            policy_id.set(None);
            scope.set("instance".into());
            scope_id.set(String::new());
            node.set(String::new());
            priority.set("0".into());
            weights.set(WeightOverrides::default());
            valid.set(true);
            error.set(None);
        })
    };
    html! {<PageSection><Stack gutter=true><Title level={Level::H2}>{"Verdict weighting"}</Title><p>{"Configure instance, group, SBOM, or component preferences. Changes apply to current evidence immediately. Group policies inherit from parent groups; higher priority wins at equal depth. Conflicting equal-priority groups require selecting a group in the verdict preview. Providers are identified through "}<Link<AppRoute> to={AppRoute::ProviderAliases}>{"provider aliases"}</Link<AppRoute>>{"."}</p>
        if let Some(e)=&*error{<Alert title="Settings error" r#type={AlertType::Danger} inline=true><p>{e}</p></Alert>}
        <Title level={Level::H3}>{"Saved policies"}</Title>
        <ul>{for policies.iter().map(|p| {
            let id=p.id;let delete=delete.clone();let edit=edit_policy.clone();let policy=p.clone();
            html!{<li>
                {format!("{} — priority {}",setting_source(&SettingOrigin {source:p.data.scope.to_string(),scope:Some(p.data.scope.clone()),..Default::default()}),p.data.priority)}
                <Button variant={ButtonVariant::Link} onclick={Callback::from(move|_:MouseEvent|edit.emit(policy.clone()))}>{"Edit"}</Button>
                <Button variant={ButtonVariant::Link} onclick={Callback::from(move|_:MouseEvent|delete.emit(("weight-policy",id)))}>{"Delete"}</Button>
            </li>}
        })}</ul>
        <Card><CardBody><Form limit_width=true onsubmit={Callback::from(|event: SubmitEvent| event.prevent_default())}>
        <Title level={Level::H3}>{if policy_id.is_some(){"Edit policy"}else{"Create policy"}}</Title>
        <Button variant={ButtonVariant::Link} onclick={new_policy}>{"New policy"}</Button>
        <FormGroup label="Scope">
            <SimpleSelect<String>
                entries={vec!["instance".to_string(),"group".to_string(),"sbom".to_string(),"component".to_string()]}
                selected={(*scope).clone()}
                onselect={{let scope=scope.clone();Callback::from(move|value:String|scope.set(value))}}/>
        </FormGroup>
        if scope.as_str()!="instance" {{text_field("Scope UUID (group or SBOM)",scope_id.clone())}}
        if scope.as_str()=="component" {{text_field("Component node ID",node.clone())}}
        if scope.as_str()=="group" {{text_field("Priority",priority.clone())}}
        <WeightEditor key={format!("{}-{}-{}",policy_id.map(|id|id.to_string()).unwrap_or_default(),*editor_generation,*generation)} value={(*weights).clone()} onchange={change}/>
        <ActionGroup><Button onclick={save} disabled={!*valid}>{"Save policy"}</Button></ActionGroup>
        </Form></CardBody></Card>
    </Stack></PageSection>}
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
