//! CVSS scores, colored by their severity rating.

use crate::{
    AppRoute,
    tools::{Tool, ToolRoute},
};
use patternfly_yew::prelude::*;
use trustify_api::correlation::{ScoreRef, ScoreSeverity};
use yew::prelude::*;
use yew_nested_router::components::Link;

/// The label color of a severity rating.
pub fn severity_color(severity: ScoreSeverity) -> Color {
    match severity {
        ScoreSeverity::Critical => Color::Red,
        ScoreSeverity::High => Color::Orange,
        ScoreSeverity::Medium => Color::Yellow,
        ScoreSeverity::Low => Color::Blue,
        ScoreSeverity::None => Color::Grey,
    }
}

/// The qualitative rating of a score. CVSS 2.0 has no "None" and "Critical" ratings.
pub fn rating(score: f64, v2: bool) -> ScoreSeverity {
    if !v2 && score == 0.0 {
        ScoreSeverity::None
    } else if score < 4.0 {
        ScoreSeverity::Low
    } else if score < 7.0 {
        ScoreSeverity::Medium
    } else if v2 || score < 9.0 {
        ScoreSeverity::High
    } else {
        ScoreSeverity::Critical
    }
}

/// A severity rating as documents state it, e.g. `CRITICAL`.
pub fn parse_severity(value: &str) -> Option<ScoreSeverity> {
    Some(match value.to_ascii_lowercase().as_str() {
        "none" => ScoreSeverity::None,
        "low" => ScoreSeverity::Low,
        "medium" => ScoreSeverity::Medium,
        "high" => ScoreSeverity::High,
        "critical" => ScoreSeverity::Critical,
        _ => return None,
    })
}

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct ScoreLabelProps {
    pub score: f64,
    pub severity: ScoreSeverity,
    /// The CVSS version, e.g. `3.1`, for the tooltip.
    #[prop_or_default]
    pub version: Option<AttrValue>,
    /// The vector, linking the label to the CVSS inspector.
    #[prop_or_default]
    pub vector: Option<AttrValue>,
}

/// A score with its rating, e.g. `9.8 Critical`, colored by the rating.
#[function_component(ScoreLabel)]
pub fn score_label(props: &ScoreLabelProps) -> Html {
    let label = html! {
        <Label
            compact=true
            label={format!("{:.1} {}", props.score, props.severity.label())}
            color={severity_color(props.severity)}
        />
    };
    let title = match (&props.version, &props.vector) {
        (Some(version), Some(vector)) => Some(format!("CVSS {version}: {vector}")),
        (Some(version), None) => Some(format!("CVSS {version}")),
        (None, Some(vector)) => Some(vector.to_string()),
        (None, None) => None,
    };
    match &props.vector {
        Some(vector) => html! {
            <Link<AppRoute> to={AppRoute::Tools(ToolRoute { tool: Tool::Cvss, value: vector.to_string() })}>
                <span {title}>{ label }</span>
            </Link<AppRoute>>
        },
        None => html!(<span {title}>{ label }</span>),
    }
}

/// The first of a verdict's scores, the newest CVSS version with the highest score.
pub fn primary_score(scores: &[ScoreRef]) -> Html {
    match scores.first() {
        Some(score) => html! {
            <ScoreLabel
                score={score.score}
                severity={score.severity}
                version={AttrValue::from(score.version.as_str())}
                vector={AttrValue::from(score.vector.clone())}
            />
        },
        None => html!("\u{2014}"),
    }
}

#[cfg(test)]
mod test {
    use super::{ScoreSeverity::*, parse_severity, rating};

    #[test]
    fn ratings() {
        assert_eq!(
            [0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0].map(|score| rating(score, false)),
            [None, Low, Medium, Medium, High, High, Critical, Critical]
        );
        // CVSS 2.0 has no "None" and "Critical" ratings
        assert_eq!(
            [0.0, 4.0, 7.0, 10.0].map(|score| rating(score, true)),
            [Low, Medium, High, High]
        );
    }

    #[test]
    fn stated_severity() {
        assert_eq!(
            ["CRITICAL", "high", "Medium", "unknown"].map(parse_severity),
            [Some(Critical), Some(High), Some(Medium), Option::None]
        );
    }
}
