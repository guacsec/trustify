//! Local validators and reusable inline links for Explore.
//! CVSS metric groups follow scm-rs/cvss-rs web/src/main.rs.

use crate::{
    AppRoute,
    score::{ScoreLabel, rating},
};
use cpe::{cpe::Cpe as _, uri::OwnedUri};
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use patternfly_yew::prelude::*;
use std::str::FromStr;
use yew::prelude::*;
use yew_nested_router::{
    components::Link,
    prelude::{Target, use_router},
};

/// An inspection tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Cvss,
    Purl,
    Cpe,
}

impl Tool {
    fn segment(self) -> &'static str {
        match self {
            Self::Cvss => "cvss",
            Self::Purl => "purl",
            Self::Cpe => "cpe",
        }
    }

    fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "cvss" => Some(Self::Cvss),
            "purl" => Some(Self::Purl),
            "cpe" => Some(Self::Cpe),
            _ => None,
        }
    }
}

/// A tool, with the value to inspect as an optional last path segment: `/tools/<tool>[/<value>]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolRoute {
    pub tool: Tool,
    pub value: String,
}

impl ToolRoute {
    /// The tool, without a value.
    pub fn empty(tool: Tool) -> Self {
        Self {
            tool,
            value: String::new(),
        }
    }

    /// Whether a route is the tool, with any value, for highlighting its navigation item.
    pub fn is_active(tool: Tool) -> Callback<AppRoute, bool> {
        Callback::from(move |route| matches!(route, AppRoute::Tools(route) if route.tool == tool))
    }
}

impl Target for ToolRoute {
    fn render_self_into(&self, path: &mut Vec<String>) {
        path.push(self.tool.segment().into());
        if !self.value.is_empty() {
            path.push(self.value.clone());
        }
    }

    fn render_path_into(&self, path: &mut Vec<String>) {
        self.render_self_into(path);
    }

    fn parse_path(path: &[&str]) -> Option<Self> {
        match path {
            [tool] => Tool::from_segment(tool).map(Self::empty),
            [tool, value] => Tool::from_segment(tool).map(|tool| Self {
                tool,
                value: value.to_string(),
            }),
            _ => None,
        }
    }
}

#[derive(Properties, PartialEq)]
pub struct InlineProps {
    pub value: AttrValue,
}
macro_rules! inline {
    ($name:ident, $fun:ident, $tool:expr, $label:literal) => {
        #[function_component($name)]
        pub fn $fun(props: &InlineProps) -> Html {
            let to = AppRoute::Tools(ToolRoute {
                tool: $tool,
                value: props.value.to_string(),
            });
            html! {
                <Link<AppRoute> {to} class="trustify-overflow-anywhere">
                    <code title={$label}>{&props.value}</code>
                </Link<AppRoute>>
            }
        }
    };
}
inline!(InlinePurl, inline_purl, Tool::Purl, "Inspect Package URL");
inline!(InlineCpe, inline_cpe, Tool::Cpe, "Inspect CPE");
inline!(InlineCvss, inline_cvss, Tool::Cvss, "Inspect CVSS");

fn fields(rows: Vec<(&str, String)>) -> Html {
    html! { <DescriptionList>{for rows.into_iter().map(|(k,v)| html!{<DescriptionGroup term={k.to_owned()}><code class="trustify-break-all">{v}</code></DescriptionGroup>})}</DescriptionList> }
}
fn score_row(label: &'static str, score: Option<f64>, v2: bool) -> Html {
    html! {
        <p>
            <strong>{label}{": "}</strong>
            if let Some(score) = score {
                <ScoreLabel {score} severity={rating(score, v2)} />
            } else {
                {"N/A"}
            }
        </p>
    }
}
macro_rules! collect_metrics {
    ($cvss:expr, $( ($field:ident, $abbr:expr, $name:expr) ),* $(,)?) => {{
        let mut rows = Vec::new();
        $(if let Some(v) = &$cvss.$field { rows.push(($name, format!("{}: {v:?}", $abbr))); })*
        rows
    }};
}
fn render_v2(cvss: CvssV2) -> Html {
    let scores =
        html! {<><p>{"CVSS 2.0"}</p>{ score_row("Base", cvss.calculated_base_score(), true) }</>};
    let extra = html! {<>{score_row("Temporal",cvss.calculated_temporal_score(),true)}{score_row("Environmental",cvss.calculated_environmental_score(),true)}</>};
    let base = collect_metrics!(
        cvss,
        (access_vector, "AV", "Access Vector"),
        (access_complexity, "AC", "Access Complexity"),
        (authentication, "Au", "Authentication"),
        (confidentiality_impact, "C", "Confidentiality Impact"),
        (integrity_impact, "I", "Integrity Impact"),
        (availability_impact, "A", "Availability Impact"),
    );
    let temporal = collect_metrics!(
        cvss,
        (exploitability, "E", "Exploitability"),
        (remediation_level, "RL", "Remediation Level"),
        (report_confidence, "RC", "Report Confidence"),
    );
    let environmental = collect_metrics!(
        cvss,
        (
            collateral_damage_potential,
            "CDP",
            "Collateral Damage Potential"
        ),
        (target_distribution, "TD", "Target Distribution"),
        (
            confidentiality_requirement,
            "CR",
            "Confidentiality Requirement"
        ),
        (integrity_requirement, "IR", "Integrity Requirement"),
        (availability_requirement, "AR", "Availability Requirement"),
    );
    html! {<>{scores}{extra}<h2>{"Base metrics"}</h2>{fields(base)}<h2>{"Temporal metrics"}</h2>{fields(temporal)}<h2>{"Environmental metrics"}</h2>{fields(environmental)}</>}
}
fn render_v3(cvss: CvssV3) -> Html {
    let scores = html! {<><p>{format!("CVSS {}", cvss.version.as_ref().map(|v|v.to_string()).unwrap_or_default())}</p>{ score_row("Base", cvss.calculated_base_score(), false) }</>};
    let extra = html! {<>{score_row("Temporal",cvss.calculated_temporal_score(),false)}{score_row("Environmental",cvss.calculated_environmental_score(),false)}</>};
    let base = collect_metrics!(
        cvss,
        (attack_vector, "AV", "Attack Vector"),
        (attack_complexity, "AC", "Attack Complexity"),
        (privileges_required, "PR", "Privileges Required"),
        (user_interaction, "UI", "User Interaction"),
        (scope, "S", "Scope"),
        (confidentiality_impact, "C", "Confidentiality Impact"),
        (integrity_impact, "I", "Integrity Impact"),
        (availability_impact, "A", "Availability Impact"),
    );
    let temporal = collect_metrics!(
        cvss,
        (exploit_code_maturity, "E", "Exploit Code Maturity"),
        (remediation_level, "RL", "Remediation Level"),
        (report_confidence, "RC", "Report Confidence"),
    );
    let environmental = collect_metrics!(
        cvss,
        (
            confidentiality_requirement,
            "CR",
            "Confidentiality Requirement"
        ),
        (integrity_requirement, "IR", "Integrity Requirement"),
        (availability_requirement, "AR", "Availability Requirement"),
        (modified_attack_vector, "MAV", "Modified Attack Vector"),
        (
            modified_attack_complexity,
            "MAC",
            "Modified Attack Complexity"
        ),
        (
            modified_privileges_required,
            "MPR",
            "Modified Privileges Required"
        ),
        (
            modified_user_interaction,
            "MUI",
            "Modified User Interaction"
        ),
        (modified_scope, "MS", "Modified Scope"),
        (
            modified_confidentiality_impact,
            "MC",
            "Modified Confidentiality Impact"
        ),
        (modified_integrity_impact, "MI", "Modified Integrity Impact"),
        (
            modified_availability_impact,
            "MA",
            "Modified Availability Impact"
        ),
    );
    html! {<>{scores}{extra}<h2>{"Base metrics"}</h2>{fields(base)}<h2>{"Temporal metrics"}</h2>{fields(temporal)}<h2>{"Environmental metrics"}</h2>{fields(environmental)}</>}
}
fn render_v4(cvss: CvssV4) -> Html {
    let scores = html! {<><p>{"CVSS 4.0"}</p>{score_row("Score",cvss.calculated_score().map(|(s,_)|s),false)}<p>{cvss.calculated_score().map(|(_,n)|n.to_string()).unwrap_or_default()}</p></>};
    let extra = html! {};
    let base = collect_metrics!(
        cvss,
        (attack_vector, "AV", "Attack Vector"),
        (attack_complexity, "AC", "Attack Complexity"),
        (attack_requirements, "AT", "Attack Requirements"),
        (privileges_required, "PR", "Privileges Required"),
        (user_interaction, "UI", "User Interaction"),
        (vuln_confidentiality_impact, "VC", "Vuln. Confidentiality"),
        (vuln_integrity_impact, "VI", "Vuln. Integrity"),
        (vuln_availability_impact, "VA", "Vuln. Availability"),
        (sub_confidentiality_impact, "SC", "Sub. Confidentiality"),
        (sub_integrity_impact, "SI", "Sub. Integrity"),
        (sub_availability_impact, "SA", "Sub. Availability"),
    );
    let threat = collect_metrics!(cvss, (exploit_maturity, "E", "Exploit Maturity"),);
    let environmental = collect_metrics!(
        cvss,
        (
            confidentiality_requirement,
            "CR",
            "Confidentiality Requirement"
        ),
        (integrity_requirement, "IR", "Integrity Requirement"),
        (availability_requirement, "AR", "Availability Requirement"),
        (modified_attack_vector, "MAV", "Modified Attack Vector"),
        (
            modified_attack_complexity,
            "MAC",
            "Modified Attack Complexity"
        ),
        (
            modified_attack_requirements,
            "MAT",
            "Modified Attack Requirements"
        ),
        (
            modified_privileges_required,
            "MPR",
            "Modified Privileges Required"
        ),
        (
            modified_user_interaction,
            "MUI",
            "Modified User Interaction"
        ),
        (
            modified_vuln_confidentiality_impact,
            "MVC",
            "Modified Vuln. Confidentiality"
        ),
        (
            modified_vuln_integrity_impact,
            "MVI",
            "Modified Vuln. Integrity"
        ),
        (
            modified_vuln_availability_impact,
            "MVA",
            "Modified Vuln. Availability"
        ),
        (
            modified_sub_confidentiality_impact,
            "MSC",
            "Modified Sub. Confidentiality"
        ),
        (
            modified_sub_integrity_impact,
            "MSI",
            "Modified Sub. Integrity"
        ),
        (
            modified_sub_availability_impact,
            "MSA",
            "Modified Sub. Availability"
        ),
    );
    let supplemental = collect_metrics!(
        cvss,
        (safety, "S", "Safety"),
        (automatable, "AU", "Automatable"),
        (recovery, "R", "Recovery"),
        (value_density, "V", "Value Density"),
        (vulnerability_response_effort, "RE", "Response Effort"),
        (provider_urgency, "U", "Provider Urgency"),
    );
    html! {<>{scores}{extra}<h2>{"Base metrics"}</h2>{fields(base)}<h2>{"Threat metrics"}</h2>{fields(threat)}<h2>{"Environmental metrics"}</h2>{fields(environmental)}<h2>{"Supplemental metrics"}</h2>{fields(supplemental)}</>}
}

fn inspect(tool: Tool, input: &str) -> Result<Html, String> {
    let value = input.trim();
    match tool {
        Tool::Cvss => {
            let upper = value.to_ascii_uppercase();
            let result = if upper.starts_with("CVSS:4.") {
                CvssV4::from_str(value).map(render_v4)
            } else if upper.starts_with("CVSS:3.") {
                CvssV3::from_str(value).map(render_v3)
            } else {
                CvssV2::from_str(value).map(render_v2)
            };
            result.map_err(|e| e.to_string())
        }
        Tool::Purl => {
            let p = packageurl::PackageUrl::from_str(value).map_err(|e| e.to_string())?;
            Ok(fields(vec![
                ("Canonical", p.to_string()),
                ("Type", p.ty().into()),
                ("Namespace", p.namespace().unwrap_or("(none)").into()),
                ("Name", p.name().into()),
                ("Version", p.version().unwrap_or("(none)").into()),
                (
                    "Qualifiers",
                    p.qualifiers()
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                ("Subpath", p.subpath().unwrap_or("(none)").into()),
            ]))
        }
        Tool::Cpe => inspect_cpe(value),
    }
}
fn split_cpe23(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                cur.push(c);
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            ':' => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
}

/// Remove `\`-escapes from a CPE 2.3 formatted string component.
fn unescape_cpe23(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Percent-encode a decoded component value using CPE 2.2 URI syntax,
/// mapping the `?`/`*` wildcards to their `%01`/`%02` special encodings.
fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '?' => out.push_str("%01"),
            '*' => out.push_str("%02"),
            c if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') => out.push(c),
            c => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{b:02x}"));
                }
            }
        }
    }
    out
}

/// Turn a raw (still escaped) CPE 2.3 component into its CPE 2.2 URI form.
fn cpe23_component_to_uri(raw: &str) -> String {
    match raw {
        // ANY is the empty component in URI syntax
        "*" => String::new(),
        "-" => "-".to_string(),
        _ => encode_uri_component(&unescape_cpe23(raw)),
    }
}

/// Convert a CPE 2.3 formatted string (`cpe:2.3:part:vendor:...`, 11 attribute
/// components) into a CPE 2.2 URI, packing the extended attributes
/// (sw_edition, target_sw, target_hw, other) into the edition component.
fn cpe23_to_uri(value: &str, body: &str) -> Result<OwnedUri, cpe::error::CpeError> {
    let invalid = || cpe::error::CpeError::InvalidUri {
        value: value.to_owned(),
    };

    let raw = split_cpe23(body);
    if raw.len() != 11 {
        return Err(invalid());
    }

    let part = match raw[0].as_str() {
        "*" | "-" => "",
        part => part,
    };

    let [vendor, product, version, update, edition] =
        [&raw[1], &raw[2], &raw[3], &raw[4], &raw[5]].map(|c| cpe23_component_to_uri(c));
    let [sw_edition, target_sw, target_hw, other] =
        [&raw[7], &raw[8], &raw[9], &raw[10]].map(|c| cpe23_component_to_uri(c));

    let edition = if [&sw_edition, &target_sw, &target_hw, &other]
        .iter()
        .all(|c| c.is_empty())
    {
        edition
    } else {
        format!("~{edition}~{sw_edition}~{target_sw}~{target_hw}~{other}")
    };

    let language = match raw[6].as_str() {
        "*" | "-" => String::new(),
        lang => unescape_cpe23(lang),
    };

    let mut components = vec![
        part.to_string(),
        vendor,
        product,
        version,
        update,
        edition,
        language,
    ];
    // the URI parser treats empty components in the middle as ANY, but fails on
    // an empty trailing language component
    while components.last().is_some_and(|c| c.is_empty()) {
        components.pop();
    }

    parse_uri(&format!("cpe:/{}", components.join(":")))
}

fn parse_uri(value: &str) -> Result<OwnedUri, cpe::error::CpeError> {
    value.parse()
}
fn inspect_cpe(value: &str) -> Result<Html, String> {
    if let Some(body) = value.strip_prefix("cpe:2.3:") {
        let p = cpe23_to_uri(value, body).map_err(|e| e.to_string())?;
        let raw = split_cpe23(body);
        let names = [
            "Part",
            "Vendor",
            "Product",
            "Version",
            "Update",
            "Edition",
            "Language",
            "Software edition",
            "Target software",
            "Target hardware",
            "Other",
        ];
        let mut rows = vec![
            ("CPE 2.3", value.to_string()),
            ("Normalized URI", format!("{p:#}")),
        ];
        rows.extend(names.into_iter().zip(raw.iter().map(|v| match v.as_str() {
            "*" => "ANY (*)".into(),
            "-" => "NA (-)".into(),
            _ => unescape_cpe23(v),
        })));
        return Ok(fields(rows));
    }

    let p = match value.strip_prefix("cpe:2.3:") {
        Some(body) => cpe23_to_uri(value, body),
        None => value.parse::<OwnedUri>(),
    }
    .map_err(|e| e.to_string())?;
    Ok(fields(vec![
        ("Normalized URI", format!("{p:#}")),
        ("Part", format!("{:?}", p.part())),
        ("Vendor", component_text(p.vendor())),
        ("Product", component_text(p.product())),
        ("Version", component_text(p.version())),
        ("Update", component_text(p.update())),
        ("Edition", component_text(p.edition())),
        ("Language", format!("{:?}", p.language())),
        ("Sw Edition", component_text(p.sw_edition())),
        ("Target Sw", component_text(p.target_sw())),
        ("Target Hw", component_text(p.target_hw())),
        ("Other", component_text(p.other())),
    ]))
}
#[derive(Properties, PartialEq)]
pub struct ToolProps {
    pub route: ToolRoute,
}
#[function_component(ToolPage)]
pub fn tool_page(props: &ToolProps) -> Html {
    let router = use_router::<AppRoute>();
    let message = use_state(String::new);
    let tool = props.route.tool;
    let input = &props.route.value;
    let onchange = {
        let router = router.clone();
        let message = message.clone();
        Callback::from(move |value: String| {
            if let Some(router) = &router {
                router.replace(AppRoute::Tools(ToolRoute { tool, value }));
            }
            message.set(String::new());
        })
    };
    let onclick = {
        let link = router.as_ref().map(|router| {
            let path = router.render_target(AppRoute::Tools(props.route.clone()));
            format!(
                "{}{path}",
                gloo_utils::window().location().origin().unwrap_or_default()
            )
        });
        let message = message.clone();
        Callback::from(move |_| {
            let Some(link) = link.clone() else {
                return;
            };
            let message = message.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let result = wasm_bindgen_futures::JsFuture::from(
                    gloo_utils::window()
                        .navigator()
                        .clipboard()
                        .write_text(&link),
                )
                .await;
                message.set(if result.is_ok() {
                    "Copied!".into()
                } else {
                    "Could not copy link. Copy the address from your browser.".into()
                });
            });
        })
    };
    let (title, placeholder) = match tool {
        Tool::Cvss => ("CVSS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        Tool::Purl => ("Package URL", "pkg:maven/org.example/demo@1.0"),
        Tool::Cpe => ("CPE", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
    };
    let empty = input.trim().is_empty();
    let result = (!empty).then(|| inspect(tool, input));
    let (state, helper_text) = match &result {
        Some(Err(error)) => (
            InputState::Error,
            Some(FormHelperText::from((
                format!("Invalid value: {error}"),
                InputState::Error,
            ))),
        ),
        _ => (InputState::Default, None),
    };
    let copy_text = if message.is_empty() {
        "Copy link".to_string()
    } else {
        (*message).clone()
    };
    html! {
        <PageSection>
            <Title level={Level::H1}>{title}</Title>
            <p>{"Validate and inspect a value. Share the current browser address or copy its link."}</p>
            <br />
            <Form onsubmit={Callback::from(|e: SubmitEvent| e.prevent_default())}>
                <FormGroup label={format!("{title} value")} {helper_text}>
                    <InputGroup>
                        <InputGroupItem fill=true>
                            <TextInput
                                id="tool-input"
                                value={input.clone()}
                                placeholder={placeholder}
                                {state}
                                {onchange}
                            />
                        </InputGroupItem>
                        <InputGroupItem plain=true>
                            <Tooltip text={copy_text}>
                                <Button
                                    variant={ButtonVariant::Plain}
                                    icon={Icon::Copy}
                                    aria_label="Copy link"
                                    {onclick}
                                    disabled={empty}
                                />
                            </Tooltip>
                        </InputGroupItem>
                    </InputGroup>
                </FormGroup>
            </Form>
            <span class="pf-v6-screen-reader" role="status">{&*message}</span>
            if let Some(Ok(result)) = result {
                <br />
                {result}
            }
        </PageSection>
    }
}

/// Render known identifier syntax using the same inspect links across evidence views.
pub fn inline_identifier(value: &str) -> Html {
    if value.starts_with("pkg:") {
        html! {<InlinePurl value={value.to_owned()} />}
    } else if value.starts_with("cpe:") {
        html! {<InlineCpe value={value.to_owned()} />}
    } else {
        html! {<code>{value}</code>}
    }
}

fn component_text(value: cpe::component::Component<'_>) -> String {
    match value {
        cpe::component::Component::Any => "ANY (*)".into(),
        cpe::component::Component::NotApplicable => "NA (-)".into(),
        cpe::component::Component::Value(v) => v.to_string(),
    }
}
