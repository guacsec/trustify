//! Shared rendering for correlation status, evidence, and component identifiers.
use crate::{
    model::{
        EvidenceRemediation, IdentifierKind, IdentifierRef, MatchedValue, RemediationCategory,
        VerdictStatus,
    },
    tools::{InlineCpe, InlinePurl, inline_identifier},
};
use patternfly_yew::prelude::*;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use trustify_api::correlation::ResolutionSummary;
use yew::prelude::*;

/// Render the identifiers of a component, grouped by kind.
pub(super) fn identifiers(identifiers: &[IdentifierRef]) -> Html {
    let mut sections = BTreeMap::<IdentifierKind, Vec<&str>>::new();
    for identifier in identifiers {
        sections
            .entry(identifier.kind)
            .or_default()
            .push(&identifier.value);
    }

    if sections.is_empty() {
        return html!(<i>{ "\u{2014}" }</i>);
    }

    html! {
        { for sections.into_iter().map(|(kind, items)| html! {
            <div>
                <strong>{ kind.label() }</strong>
                <ul style="margin:0;padding-left:1em">
                    { for items.iter().map(|value| html!(<li>{ identifier(kind, value) }</li>)) }
                </ul>
            </div>
        })}
    }
}

/// Render an identifier, linking PURLs and CPEs to their inspector.
fn identifier(kind: IdentifierKind, value: &str) -> Html {
    let value = value.to_owned();
    match kind {
        IdentifierKind::Purl => html!(<InlinePurl {value} />),
        IdentifierKind::Cpe => html!(<InlineCpe {value} />),
        _ => html!(<code>{ value }</code>),
    }
}

/// Render the advisory side of a match: the identifier, and each matched version range on a line
/// of its own.
pub(crate) fn matched_value(value: &MatchedValue) -> Html {
    html! {
        <>
            { inline_identifier(&value.identifier) }
            if !value.ranges.is_empty() {
                <ul style="margin:0;padding-left:1em">
                    { for value.ranges.iter().map(|range| html!(<li>{ range.to_string() }</li>)) }
                </ul>
            }
            if let Some(enabled_by) = &value.enabled_by {
                <div>
                    <small>
                        { "enabled by option " }
                        <code>{ enabled_by.key.as_str() }</code>
                        { " for " }
                        <code>{ &enabled_by.publisher_namespace }</code>
                        if let Some(reason) = &enabled_by.reason {
                            { ": " }{ reason }
                        }
                    </small>
                </div>
            }
        </>
    }
}

/// A timestamp to the second, without the offset when in UTC. The tooltip has the full value.
pub(crate) fn timestamp(value: &OffsetDateTime) -> Html {
    let offset = value.offset();
    let mut short = format!(
        "{} {:02}:{:02}:{:02}",
        value.date(),
        value.hour(),
        value.minute(),
        value.second()
    );
    if !offset.is_utc() {
        let sign = if offset.is_negative() { '-' } else { '+' };
        short.push_str(&format!(
            " {sign}{:02}:{:02}",
            offset.whole_hours().unsigned_abs(),
            offset.minutes_past_hour().unsigned_abs()
        ));
    }
    html! {
        <Tooltip text={value.to_string()}>
            <span>{ short }</span>
        </Tooltip>
    }
}

/// The color of a verdict status, the same as of the statuses of advisories.
pub(crate) fn status_color(status: VerdictStatus) -> Color {
    match status {
        VerdictStatus::Affected => Color::Red,
        VerdictStatus::Fixed => Color::Blue,
        VerdictStatus::NotAffected => Color::Green,
        VerdictStatus::UnderInvestigation => Color::Orange,
        VerdictStatus::None => Color::Grey,
    }
}

/// The selected match confidence of a verdict as a label, e.g. "55%", explained on hover. A
/// conflict among the evidence is shown as a label of its own.
pub(crate) fn confidence_label(resolution: &ResolutionSummary) -> Html {
    let percent = format!("{:.0}%", resolution.confidence * 100.0);
    html! {
        <>
            <Tooltip text={format!("Confidence: {percent}")}>
                <Label compact=true outline=true label={percent.clone()} />
            </Tooltip>
            if resolution.has_conflict {
                <Tooltip text="Evidence states different statuses">
                    <Label compact=true color={Color::Orange} label="Conflict" />
                </Tooltip>
            }
        </>
    }
}

pub(super) fn status_label(status: VerdictStatus) -> Html {
    html! { <Label label={status.label()} color={status_color(status)} /> }
}

/// A remediation, e.g. "Fixed in 4.1.2", or its category and details.
pub(super) fn remediation(remediation: &EvidenceRemediation) -> Html {
    let text = match (&remediation.category, &remediation.details) {
        // a vendor fix's details already say what fixes it
        (RemediationCategory::VendorFix, Some(details)) => details.clone(),
        (category, Some(details)) => format!("{}: {details}", category.label()),
        (category, None) => category.label().to_string(),
    };
    html! {
        <span>
            <i class="fas fa-wrench pf-v6-u-mr-xs" aria-hidden="true"/>
            if let Some(url) = &remediation.url {
                <a href={url.clone()} target="_blank" rel="noopener noreferrer">{ text }</a>
            } else {
                { text }
            }
        </span>
    }
}
