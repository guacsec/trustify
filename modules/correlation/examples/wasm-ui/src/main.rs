//! Browser UI for loading advisory/SBOM data and inspecting verdicts.

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use leptos::prelude::*;
use trustify_module_correlation::{
    collector::VecCollector,
    engine::correlate_with_options,
    evidence::{AdvisoryEvidence, Evidence, SbomEvidence},
    extract,
    memory::AdvisoryIndex,
    options::{
        CorrelationOptions, NoneVerdictPolicy, ProductMatchPolicy, ResolutionPolicy, TraceOptions,
        VersionlessMatchPolicy,
    },
    types::{ComponentId, ComponentQuery, Verdict, parse_purl},
};
use wasm_bindgen::prelude::*;

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}

#[derive(Clone, Debug)]
struct VerdictDisplay {
    vulnerability_id: String,
    status: String,
    status_class: String,
    confidence: String,
    assertions: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryMode {
    Purl,
    Cpe,
    Digest,
    Sbom,
}

fn status_class(status: &str) -> String {
    format!("status-{status}")
}

fn component_evidence(advisory: AdvisoryEvidence, query: &ComponentQuery) -> Evidence {
    Evidence::new(
        advisory,
        SbomEvidence {
            name: "component-query".into(),
            components: vec![trustify_module_correlation::types::SbomComponent {
                id: query.id.clone(),
                context: query.context.clone(),
                grouping: query.grouping.clone(),
            }],
            context: Vec::new(),
            grouping: Vec::new(),
        },
    )
}

fn with_requested_vulnerabilities(mut evidence: Evidence, raw: &str) -> Evidence {
    evidence.requested_vulnerabilities = raw
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect();
    evidence
}

/// Read a file and deliver its content as a JSON string.
/// If the filename ends with `.xz`, the bytes are decompressed first.
fn read_file(
    file: &web_sys::File,
    on_ok: impl FnOnce(String, String) + 'static,
    on_err: impl FnOnce(String) + 'static,
) {
    let name = file.name();
    let reader = web_sys::FileReader::new().unwrap();
    let reader_clone = reader.clone();

    let closure = Closure::once(Box::new(move || {
        let Some(result) = reader_clone.result().ok() else {
            on_err(format!("Failed to read {name}"));
            return;
        };

        let bytes = js_sys::Uint8Array::new(&result).to_vec();

        let json_bytes = if name.ends_with(".xz") {
            match decompress_xz(&bytes) {
                Ok(b) => b,
                Err(e) => {
                    on_err(format!("Failed to decompress {name}: {e}"));
                    return;
                }
            }
        } else {
            bytes
        };

        match String::from_utf8(json_bytes) {
            Ok(content) => on_ok(name, content),
            Err(e) => on_err(format!("Invalid UTF-8 in {name}: {e}")),
        }
    }) as Box<dyn FnOnce()>);

    reader.set_onloadend(Some(closure.as_ref().unchecked_ref()));
    closure.forget();
    let _ = reader.read_as_array_buffer(file);
}

fn decompress_xz(data: &[u8]) -> Result<Vec<u8>, lzma_rs::error::Error> {
    let mut output = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::Cursor::new(data), &mut output)?;
    Ok(output)
}

#[component]
fn App() -> impl IntoView {
    let advisories = Rc::new(RefCell::new(AdvisoryIndex::new()));
    let (advisory_names, set_advisory_names) = signal(Vec::<String>::new());
    let (assertion_count, set_assertion_count) = signal(0usize);
    let (sbom_data, set_sbom_data) = signal(Option::<(String, serde_json::Value)>::None);
    let (purl_input, set_purl_input) = signal(String::new());
    let (cpe_input, set_cpe_input) = signal(String::new());
    let (digest_input, set_digest_input) = signal(String::new());
    let (results, set_results) = signal(Vec::<VerdictDisplay>::new());
    let (trace_log, set_trace_log) = signal(String::new());
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (mode, set_mode) = signal(QueryMode::Purl);
    let (adv_dragging, set_adv_dragging) = signal(false);
    let (sbom_dragging, set_sbom_dragging) = signal(false);
    let (allow_versionless_matches, set_allow_versionless_matches) = signal(false);
    let (product_match_policy, set_product_match_policy) =
        signal(ProductMatchPolicy::Allow);
    let (resolution_policy, set_resolution_policy) = signal(ResolutionPolicy::Conservative);
    let (none_verdict_policy, set_none_verdict_policy) = signal(NoneVerdictPolicy::AllKnown);
    let (trace_enabled, set_trace_enabled) = signal(true);
    let (requested_vulnerabilities, set_requested_vulnerabilities) = signal(String::new());

    // Track advisory loads so the effect re-runs when advisories change
    let (advisory_version, set_advisory_version) = signal(0u32);

    let engine_for_clear = advisories.clone();
    let clear_advisories = move |_| {
        *engine_for_clear.borrow_mut() = AdvisoryIndex::new();
        set_advisory_names.set(Vec::new());
        set_assertion_count.set(0);
        set_advisory_version.update(|v| *v += 1);
    };

    let engine_for_drop = advisories.clone();
    let on_advisory_drop = move |ev: web_sys::DragEvent| {
        ev.prevent_default();
        set_adv_dragging.set(false);

        let Some(dt) = ev.data_transfer() else { return };
        let Some(files) = dt.files() else { return };

        for i in 0..files.length() {
            let Some(file) = files.get(i) else { continue };
            let eng = engine_for_drop.clone();
            read_file(
                &file,
                move |name, content| match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(json) => match extract::extract_advisory(&name, &json) {
                        Some(evidence) => {
                            let mut eng = eng.borrow_mut();
                            eng.add(evidence);
                            set_assertion_count.set(eng.assertion_count());
                            set_advisory_names.update(|names| names.push(name));
                            set_advisory_version.update(|v| *v += 1);
                            set_error_msg.set(None);
                        }
                        None => {
                            set_error_msg.set(Some(format!("Unrecognized advisory format: {name}")));
                        }
                    },
                    Err(e) => {
                        set_error_msg.set(Some(format!("Failed to parse {name}: {e}")));
                    }
                },
                move |e| set_error_msg.set(Some(e)),
            );
        }
    };

    let on_sbom_drop = move |ev: web_sys::DragEvent| {
        ev.prevent_default();
        set_sbom_dragging.set(false);

        let Some(dt) = ev.data_transfer() else { return };
        let Some(files) = dt.files() else { return };

        if let Some(file) = files.get(0) {
            read_file(
                &file,
                move |name, content| match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(json) => {
                        set_sbom_data.set(Some((name, json)));
                        set_error_msg.set(None);
                    }
                    Err(e) => {
                        set_error_msg.set(Some(format!("Failed to parse SBOM: {e}")));
                    }
                },
                move |e| set_error_msg.set(Some(e)),
            );
        }
    };

    let engine_for_correlate = advisories.clone();
    Effect::new(move || {
        let current_mode = mode.get();
        advisory_version.get();

        set_error_msg.set(None);
        set_results.set(Vec::new());
        set_trace_log.set(String::new());

        let eng = engine_for_correlate.borrow();
        let requested_vulnerabilities = requested_vulnerabilities.get();
        let options = CorrelationOptions {
            versionless_matches: if allow_versionless_matches.get() {
                VersionlessMatchPolicy::Allow
            } else {
                VersionlessMatchPolicy::Reject
            },
            product_matches: product_match_policy.get(),
            resolution: resolution_policy.get(),
            none_verdicts: none_verdict_policy.get(),
            trace: TraceOptions {
                enabled: trace_enabled.get(),
            },
        };

        match current_mode {
            QueryMode::Purl => {
                let input = purl_input.get();
                if input.trim().is_empty() {
                    return;
                }

                let Some(component_id) = parse_purl(input.trim()) else {
                    set_error_msg.set(Some(format!("Invalid PURL: {}", input.trim())));
                    return;
                };

                let mut collector = VecCollector::default();
                let query = ComponentQuery {
                    id: component_id,
                    context: Vec::new(),
                    grouping: Vec::new(),
                };
                let evidence = with_requested_vulnerabilities(
                    component_evidence(eng.evidence(), &query),
                    &requested_vulnerabilities,
                );
                let verdicts = correlate_with_options(&evidence, &options, &mut collector);
                apply_results(&verdicts, &collector, &set_results, &set_trace_log);
            }
            QueryMode::Cpe => {
                let input = cpe_input.get();
                if input.trim().is_empty() {
                    return;
                }

                let mut collector = VecCollector::default();
                let query = ComponentQuery {
                    id: ComponentId::Cpe(input.trim().to_string()),
                    context: Vec::new(),
                    grouping: Vec::new(),
                };
                let evidence = with_requested_vulnerabilities(
                    component_evidence(eng.evidence(), &query),
                    &requested_vulnerabilities,
                );
                let verdicts = correlate_with_options(&evidence, &options, &mut collector);
                apply_results(&verdicts, &collector, &set_results, &set_trace_log);
            }
            QueryMode::Digest => {
                let input = digest_input.get();
                if input.trim().is_empty() {
                    return;
                }

                let trimmed = input.trim();
                let (algorithm, value) = trimmed.split_once(':').unwrap_or(("sha256", trimmed));

                let mut collector = VecCollector::default();
                let query = ComponentQuery {
                    id: ComponentId::Hash {
                        algorithm: algorithm.to_string(),
                        value: value.to_string(),
                    },
                    context: Vec::new(),
                    grouping: Vec::new(),
                };
                let evidence = with_requested_vulnerabilities(
                    component_evidence(eng.evidence(), &query),
                    &requested_vulnerabilities,
                );
                let verdicts = correlate_with_options(&evidence, &options, &mut collector);
                apply_results(&verdicts, &collector, &set_results, &set_trace_log);
            }
            QueryMode::Sbom => {
                let data = sbom_data.get();
                let Some((name, json)) = data else {
                    return;
                };

                let mut collector = VecCollector::default();
                let sbom = extract::extract_sbom(&name, &json);

                if sbom.is_none() {
                    set_error_msg.set(Some("Failed to parse SBOM format".into()));
                    return;
                }
                let evidence = with_requested_vulnerabilities(
                    Evidence::new(eng.evidence(), sbom.unwrap()),
                    &requested_vulnerabilities,
                );
                let verdicts = correlate_with_options(&evidence, &options, &mut collector);
                apply_results(&verdicts, &collector, &set_results, &set_trace_log);
            }
        }
    });

    view! {
        <main class="app">
            <h1>"Trustify Correlation Engine"</h1>
            <p class="subtitle">
                "Drop advisory files, then query by PURL, CPE, or digest \u{2014} or correlate an SBOM."
            </p>

            {move || error_msg.get().map(|msg| view! {
                <div class="error">{msg}</div>
            })}

            // Step 1: Load advisories
            <section>
                <h2>"1. Load Advisories"</h2>
                <div
                    on:drop=on_advisory_drop
                    on:dragover=move |ev: web_sys::DragEvent| {
                        ev.prevent_default();
                        set_adv_dragging.set(true);
                    }
                    on:dragleave=move |_| set_adv_dragging.set(false)
                    class=move || if adv_dragging.get() { "dropzone active" } else { "dropzone" }
                >
                    "Drop advisory files here (CSAF, CVE, OSV \u{2014} .json or .json.xz)"
                </div>
                <div class="hint-row">
                    <span class="hint">
                        {move || {
                            let names = advisory_names.get();
                            let count = assertion_count.get();
                            if names.is_empty() {
                                "No advisories loaded".to_string()
                            } else {
                                format!("{} advisories loaded ({count} assertions): {}", names.len(), names.join(", "))
                            }
                        }}
                    </span>
                    <button
                        on:click=clear_advisories
                        class="btn-clear"
                        style=move || if advisory_names.get().is_empty() { "display:none" } else { "" }
                    >"Clear"</button>
                </div>
            </section>

            // Step 2: Query
            <section>
                <h2>"2. Query"</h2>
                <label class="option-toggle">
                    <input
                        type="checkbox"
                        prop:checked=move || allow_versionless_matches.get()
                        on:change=move |ev| {
                            set_allow_versionless_matches.set(event_target_checked(&ev));
                        }
                    />
                    "Allow version-constrained assertions to match versionless components"
                </label>
                <div class="hint">
                    "Off by default; enabling this can broaden advisory applicability."
                </div>
                <label>
                    "Requested vulnerability IDs (comma-separated)"
                    <input
                        type="text"
                        class="query-input"
                        placeholder="CVE-2024-1234, GHSA-example"
                        prop:value=move || requested_vulnerabilities.get()
                        on:input=move |ev| {
                            set_requested_vulnerabilities.set(event_target_value(&ev));
                        }
                    />
                </label>
                <div class="option-grid">
                    <label>
                        "Product matches"
                        <select
                            prop:value=move || match product_match_policy.get() {
                                ProductMatchPolicy::Allow => "allow",
                                ProductMatchPolicy::EvidenceOnly => "evidence_only",
                                ProductMatchPolicy::Reject => "reject",
                            }
                            on:change=move |ev| {
                                set_product_match_policy.set(match event_target_value(&ev).as_str() {
                                    "evidence_only" => ProductMatchPolicy::EvidenceOnly,
                                    "reject" => ProductMatchPolicy::Reject,
                                    _ => ProductMatchPolicy::Allow,
                                });
                            }
                        >
                            <option value="allow">"Allow"</option>
                            <option value="evidence_only">"Evidence only"</option>
                            <option value="reject">"Reject"</option>
                        </select>
                    </label>
                    <label>
                        "Resolution"
                        <select
                            prop:value=move || match resolution_policy.get() {
                                ResolutionPolicy::Conservative => "conservative",
                                ResolutionPolicy::SpecificityFirst => "specificity_first",
                            }
                            on:change=move |ev| {
                                set_resolution_policy.set(match event_target_value(&ev).as_str() {
                                    "specificity_first" => ResolutionPolicy::SpecificityFirst,
                                    _ => ResolutionPolicy::Conservative,
                                });
                            }
                        >
                            <option value="conservative">"Conservative"</option>
                            <option value="specificity_first">"Specificity first"</option>
                        </select>
                    </label>
                    <label>
                        "None verdicts"
                        <select
                            prop:value=move || match none_verdict_policy.get() {
                                NoneVerdictPolicy::AllKnown => "all_known",
                                NoneVerdictPolicy::IdentityMatched => "identity_matched",
                                NoneVerdictPolicy::ExplicitlyQueried => "explicitly_queried",
                            }
                            on:change=move |ev| {
                                set_none_verdict_policy.set(match event_target_value(&ev).as_str() {
                                    "identity_matched" => NoneVerdictPolicy::IdentityMatched,
                                    "explicitly_queried" => NoneVerdictPolicy::ExplicitlyQueried,
                                    _ => NoneVerdictPolicy::AllKnown,
                                });
                            }
                        >
                            <option value="all_known">"All known"</option>
                            <option value="identity_matched">"Identity matched"</option>
                            <option value="explicitly_queried">"Explicitly queried"</option>
                        </select>
                    </label>
                    <label class="option-toggle">
                        <input
                            type="checkbox"
                            prop:checked=move || trace_enabled.get()
                            on:change=move |ev| {
                                set_trace_enabled.set(event_target_checked(&ev));
                            }
                        />
                        "Decision trace"
                    </label>
                </div>

                <div style="margin-bottom: 8px;">
                    <button
                        on:click=move |_| set_mode.set(QueryMode::Purl)
                        class=move || if mode.get() == QueryMode::Purl { "btn selected" } else { "btn" }
                    >"PURL"</button>
                    <button
                        on:click=move |_| set_mode.set(QueryMode::Cpe)
                        class=move || if mode.get() == QueryMode::Cpe { "btn selected" } else { "btn" }
                    >"CPE"</button>
                    <button
                        on:click=move |_| set_mode.set(QueryMode::Digest)
                        class=move || if mode.get() == QueryMode::Digest { "btn selected" } else { "btn" }
                    >"Digest"</button>
                    <button
                        on:click=move |_| set_mode.set(QueryMode::Sbom)
                        class=move || if mode.get() == QueryMode::Sbom { "btn selected" } else { "btn" }
                    >"SBOM"</button>
                </div>

                {move || match mode.get() {
                    QueryMode::Purl => view! {
                        <div>
                            <input
                                type="text"
                                class="query-input"
                                placeholder="pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=x86_64&epoch=1"
                                prop:value=move || purl_input.get()
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_purl_input.set(val);
                                }
                            />
                        </div>
                    }.into_any(),
                    QueryMode::Cpe => view! {
                        <div>
                            <input
                                type="text"
                                class="query-input"
                                placeholder="cpe:/o:redhat:enterprise_linux:8"
                                prop:value=move || cpe_input.get()
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_cpe_input.set(val);
                                }
                            />
                        </div>
                    }.into_any(),
                    QueryMode::Digest => view! {
                        <div>
                            <input
                                type="text"
                                class="query-input"
                                placeholder="sha256:abcdef1234... or just the hex value"
                                prop:value=move || digest_input.get()
                                on:input=move |ev| {
                                    let val = event_target_value(&ev);
                                    set_digest_input.set(val);
                                }
                            />
                        </div>
                    }.into_any(),
                    QueryMode::Sbom => view! {
                        <div>
                            <div
                                on:drop=on_sbom_drop
                                on:dragover=move |ev: web_sys::DragEvent| {
                                    ev.prevent_default();
                                    set_sbom_dragging.set(true);
                                }
                                on:dragleave=move |_| set_sbom_dragging.set(false)
                                class=move || if sbom_dragging.get() { "dropzone sbom active" } else { "dropzone" }
                            >
                                "Drop SBOM file here (CycloneDX or SPDX \u{2014} .json or .json.xz)"
                            </div>
                            <div class="hint">
                                {move || match sbom_data.get() {
                                    Some((name, _)) => format!("SBOM loaded: {name}"),
                                    None => "No SBOM loaded".to_string(),
                                }}
                            </div>
                        </div>
                    }.into_any(),
                }}

            </section>

            // Results
            <section>
                <h2>"Results"</h2>
                {move || {
                    let verdicts = results.get();
                    if verdicts.is_empty() {
                        view! { <p class="no-results">"No results yet."</p> }.into_any()
                    } else {
                        let count = verdicts.len();
                        let affected_count = verdicts.iter().filter(|v| v.status == "affected").count();
                        let rows = verdicts.into_iter().map(|v| {
                            view! {
                                <tr>
                                    <td class="vuln-id">{v.vulnerability_id}</td>
                                    <td class=format!("status {}", v.status_class)>{v.status}</td>
                                    <td class="confidence">{v.confidence}</td>
                                    <td class="sources">{v.assertions}</td>
                                </tr>
                            }
                        }).collect::<Vec<_>>();

                        view! {
                            <div>
                                <p class="results-summary">
                                    {format!("{count} vulnerabilities ({affected_count} affected)")}
                                </p>
                                <table class="results-table">
                                    <thead>
                                        <tr>
                                            <th>"Vulnerability"</th>
                                            <th>"Status"</th>
                                            <th>"Confidence"</th>
                                            <th>"Sources"</th>
                                        </tr>
                                    </thead>
                                    <tbody>{rows}</tbody>
                                </table>
                            </div>
                        }.into_any()
                    }
                }}
            </section>

            // Decision trace
            <section>
                <details>
                    <summary class="trace-toggle">"Decision Trace"</summary>
                    <pre class="trace-pre">
                        {move || trace_log.get()}
                    </pre>
                </details>
            </section>
        </main>
    }
}

fn apply_results(
    verdicts: &[Verdict],
    collector: &VecCollector,
    set_results: &WriteSignal<Vec<VerdictDisplay>>,
    set_trace_log: &WriteSignal<String>,
) {
    let mut verdict_map = HashMap::<String, VerdictDisplay>::new();
    for v in verdicts {
        let status_str = v.status.as_str().to_string();
        let display = VerdictDisplay {
            vulnerability_id: v.vulnerability_id.clone(),
            status_class: status_class(&status_str),
            status: status_str,
            confidence: format!(
                "{} ({}%)",
                v.confidence.tier.as_str(),
                v.confidence.score
            ),
            assertions: v
                .contributing_assertions
                .iter()
                .map(|a| format!("{} ({})", a.source.identifier, a.status.as_str()))
                .collect::<Vec<_>>()
                .join(", "),
        };
        let existing = verdict_map.get(&v.vulnerability_id);
        let dominated = existing
            .as_ref()
            .is_some_and(|e| e.status == "fixed" || e.status == "not_affected");
        if !dominated {
            verdict_map.insert(v.vulnerability_id.clone(), display);
        }
    }

    let mut verdicts: Vec<_> = verdict_map.into_values().collect();
    verdicts.sort_by(|a, b| a.vulnerability_id.cmp(&b.vulnerability_id));
    set_results.set(verdicts);

    let mut trace_text = String::new();
    for t in &collector.trace {
        trace_text.push_str(&t.message);
        if let Some(ref d) = t.detail {
            trace_text.push_str("\n      ");
            trace_text.push_str(d);
        }
        trace_text.push('\n');
    }
    set_trace_log.set(trace_text);
}
