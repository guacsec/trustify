//! How a match confidence comes about, with all factors it can be made of.
use crate::{
    api,
    resolution::{factor_label, factor_text, percent, rule_text},
};
use patternfly_yew::prelude::*;
use trustify_api::correlation::*;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

/// The groups of factors, by what they are about.
const GROUPS: [(&str, &str); 4] = [
    (
        "Match method",
        "How the component was matched to the advisory. Every match has one of these.",
    ),
    (
        "Version range",
        "Applies when the status is not stated for the version itself, but derived from what the advisory states.",
    ),
    (
        "RPM release stream",
        "Applies to RPMs, depending on how the release streams of the RPM and the statement relate.",
    ),
    (
        "Product context",
        "Applies when the advisory states the status within a product: whether, and by what, the SBOM confirms that product.",
    ),
];

fn group(reason: &ConfidenceReason) -> usize {
    match reason {
        ConfidenceReason::Digest
        | ConfidenceReason::ProductIdentifier
        | ConfidenceReason::CpeExactVersion
        | ConfidenceReason::CpeVersionRange
        | ConfidenceReason::CpeAnyVersion
        | ConfidenceReason::Purl => 0,
        ConfidenceReason::DefaultStatus | ConfidenceReason::Rule { .. } => 1,
        ConfidenceReason::RpmStream { .. } => 2,
        ConfidenceReason::ProductConfirmed { .. } | ConfidenceReason::ProductNotConfirmed => 3,
    }
}

/// The name and description of a factor.
fn describe(info: &ConfidenceFactorInfo) -> (Html, String) {
    match &info.reason {
        ConfidenceReason::Rule { rule } => (html!(<code>{ rule }</code>), rule_text(rule)),
        ConfidenceReason::ProductConfirmed { source, .. } => {
            let mut text = format!("The product is confirmed by the {}.", source.label());
            if let Some(PerHop { step, min }) = info.per_hop {
                text.push_str(&format!(
                    " Lowered by {} for each further hop, down to {}.",
                    percent(step),
                    percent(min)
                ));
            }
            (html!(format!("Confirmed by the {}", source.label())), text)
        }
        _ => {
            let factor = ConfidenceFactor::new(info.reason.clone(), info.factor);
            (html!(factor_label(&factor)), factor_text(&factor, &[]))
        }
    }
}

fn factor_row(info: &ConfidenceFactorInfo) -> Html {
    let (label, text) = describe(info);
    html! {
        <>
            <GridItem cols={[12.all(), 8.md()]}>
                <strong>{ label }</strong>
                <div class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">{ text }</div>
            </GridItem>
            <GridItem cols={[12.all(), 4.md()]}>
                <Progress value={info.factor} size={ProgressSize::Small} />
            </GridItem>
        </>
    }
}

fn catalog_view(catalog: &ConfidenceCatalog) -> Html {
    html! {
        { for GROUPS.iter().enumerate().map(|(index, (title, description))| html! {
            <>
                <Title level={Level::H2}>{ *title }</Title>
                <p class="pf-v6-u-text-color-subtle">{ *description }</p>
                if index == 3 {
                    <p class="pf-v6-u-text-color-subtle">
                        { format!(
                            "A product confirmed through a CPE attribute of ANY, instead of an equal value, is lowered to {} of its factor.",
                            percent(catalog.wildcard_cpe)
                        ) }
                    </p>
                }
                <Grid gutter=true>
                    { for catalog.factors.iter().filter(|f| group(&f.reason) == index).map(factor_row) }
                </Grid>
            </>
        }) }
    }
}

#[function_component(ConfidencePage)]
pub fn confidence_page() -> Html {
    let catalog = use_state(|| Option::<Result<ConfidenceCatalog, String>>::None);
    let token = use_latest_access_token().and_then(|t| t.access_token());

    {
        let catalog = catalog.clone();
        use_effect_with((), move |()| {
            spawn_local(async move {
                catalog.set(Some(
                    api::fetch_confidence_catalog(token.as_deref())
                        .await
                        .map_err(|e| e.to_string()),
                ));
            });
        });
    }

    html! {
        <PageSection>
            <Content>
                <Title>{ "Match confidence" }</Title>
                <p>
                    { "Each piece of evidence has a match confidence: how certain it is that the advisory's statement is about the component. \
                       It is the product of the factors below, rounded to whole percent. \
                       For example, a CPE stating the component's exact version (80%) within a product confirmed by the SBOM's describing CPE (80%) \
                       gives 80% × 80% = 64%." }
                </p>
                <p>
                    { "When evidence disagrees, the verdict follows the strongest evidence: first by how closely the advisory's provider relates to the component, \
                       then statements made directly over derived ones, then the higher match confidence, then the more severe status." }
                </p>
                <p class="pf-v6-u-text-color-subtle">
                    { "These percentages are matching heuristics, not the probability that the component is vulnerable." }
                </p>
            </Content>
            <br />
            {
                match &*catalog {
                    None => html!(<Bullseye><Spinner /></Bullseye>),
                    Some(Err(err)) => html! {
                        <Alert title="Failed to load the confidence factors" r#type={AlertType::Danger} inline=true>
                            <p>{ err }</p>
                        </Alert>
                    },
                    Some(Ok(catalog)) => html!(<Content>{ catalog_view(catalog) }</Content>),
                }
            }
        </PageSection>
    }
}
