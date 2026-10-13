//! The CPE applicability statements (`cpeApplicability`) of a CVE record, of all its containers.
//!
//! They use the CPE Applicability Language, as NVD configurations do: nodes of CPE matches, combined
//! by `AND`/`OR`. Correlation uses the vulnerable matches. The non-vulnerable ones (e.g. the platform
//! of an `AND` configuration) don't scope them yet.

use super::{Configuration, CpeMatch, Doc, provider_label};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct ApplicabilityTabProps {
    pub doc: Doc,
}

/// The versions of a CPE match, e.g. `>= 5.4.262, < 5.4.269`, `None` without bounds (the version of
/// the CPE).
fn match_versions(cpe_match: &CpeMatch) -> Option<String> {
    let low = match (
        &cpe_match.version_start_including,
        &cpe_match.version_start_excluding,
    ) {
        (Some(v), _) => Some(format!(">= {v}")),
        (_, Some(v)) => Some(format!("> {v}")),
        _ => None,
    };
    let high = match (
        &cpe_match.version_end_including,
        &cpe_match.version_end_excluding,
    ) {
        (Some(v), _) => Some(format!("<= {v}")),
        (_, Some(v)) => Some(format!("< {v}")),
        _ => None,
    };
    match (low, high) {
        (Some(low), Some(high)) => Some(format!("{low}, {high}")),
        (Some(bound), None) | (None, Some(bound)) => Some(bound),
        (None, None) => None,
    }
}

fn configuration_card(n: usize, configuration: &Configuration) -> Html {
    let operator = configuration.operator.as_deref().unwrap_or("OR");
    html! {
        <Card size={CardSize::Compact}>
            <CardTitle>
                <Flex space_items={[SpaceItems::Small]} modifiers={[FlexModifier::Align(Alignment::Center)]}>
                    <FlexItem><strong>{ format!("Configuration #{}", n + 1) }</strong></FlexItem>
                    <FlexItem><Label label={operator.to_string()} compact=true /></FlexItem>
                    { for configuration.negate.then(|| html_nested! {
                        <FlexItem><Label label="negated" color={Color::Orange} compact=true /></FlexItem>
                    }) }
                </Flex>
            </CardTitle>
            <CardBody>
                <Stack gutter=true>
                    { for configuration.nodes.iter().map(|node| html_nested! {
                        <StackItem>
                            <small>
                                { format!("Node ({})", node.operator.as_deref().unwrap_or("OR")) }
                                if node.negate { { ", negated" } }
                            </small>
                            <List>
                                { for node.cpe_match.iter().map(|cpe_match| html_nested! {
                                    <ListItem>
                                        if cpe_match.vulnerable {
                                            <Label label="vulnerable" color={Color::Red} compact=true />
                                        } else {
                                            <Label label="not vulnerable" color={Color::Grey} compact=true />
                                        }
                                        { " " }
                                        <code>{ &cpe_match.criteria }</code>
                                        if let Some(versions) = match_versions(cpe_match) {
                                            { " " }<code>{ versions }</code>
                                        }
                                    </ListItem>
                                }) }
                            </List>
                        </StackItem>
                    }) }
                </Stack>
            </CardBody>
        </Card>
    }
}

#[function_component(ApplicabilityTab)]
pub fn applicability_tab(props: &ApplicabilityTabProps) -> Html {
    let containers = props.doc.containers();
    let containers = containers
        .iter()
        .filter(|container| !container.applicability.is_empty())
        .collect::<Vec<_>>();

    if containers.is_empty() {
        return html! {
            <EmptyState title="No CPE applicability" icon={Icon::InfoCircle} size={Size::XXXXLarge}>
                { "The record does not contain CPE applicability statements." }
            </EmptyState>
        };
    }

    html! {
        <Stack gutter=true>
            { for containers.into_iter().map(|container| html_nested! {
                <StackItem>
                    <Stack gutter=true>
                        <StackItem>{ provider_label(container) }</StackItem>
                        { for container.applicability.iter().enumerate().map(|(n, configuration)| html_nested! {
                            <StackItem>{ configuration_card(n, configuration) }</StackItem>
                        }) }
                    </Stack>
                </StackItem>
            }) }
        </Stack>
    }
}

#[cfg(test)]
mod test {
    use super::{super::parse, match_versions};

    const KERNEL: &str = include_str!(
        "../../../../etc/test-data/scenarios/S26_cve_cpe_applicability_kernel/cve/CVE-2024-26581.json"
    );

    /// The kernel ranges of CVE-2024-26581.
    #[test]
    fn versions_of_matches() {
        let doc = parse(KERNEL).expect("record parses");
        assert_eq!(
            doc.applicability[0][0].nodes[0]
                .cpe_match
                .iter()
                .map(match_versions)
                .collect::<Vec<_>>(),
            [
                Some(">= 5.4.262, < 5.4.269".to_string()),
                Some(">= 5.10.190, < 5.10.210".to_string()),
                Some(">= 5.15.124, < 5.15.149".to_string()),
                Some(">= 6.1.43, < 6.1.78".to_string()),
                Some(">= 6.5, < 6.6.17".to_string()),
                Some(">= 6.5, < 6.7.5".to_string()),
                Some(">= 6.5, < 6.8".to_string()),
                Some(">= 6.4.8".to_string()),
            ]
        );
    }
}
