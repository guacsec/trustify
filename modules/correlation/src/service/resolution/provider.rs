use crate::{error::Error, model::*};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct ResolutionContext {
    pub aliases: Vec<ProviderAlias>,
    pub component_provider: Option<String>,
    pub product_context: Vec<IdentifierRef>,
}

impl ResolutionContext {
    pub fn new(aliases: Vec<ProviderAlias>, request: &ResolutionRequest) -> Result<Self, Error> {
        let component_provider = request
            .component_provider
            .as_ref()
            .map(|p| p.trim().trim_end_matches('/').to_string());
        if component_provider.as_ref().is_some_and(String::is_empty) {
            return Err(Error::BadRequest(
                "component_provider must not be empty".into(),
            ));
        }
        Ok(Self {
            aliases,
            component_provider,
            product_context: request.product_context.clone(),
        })
    }

    pub fn revision(&self, component: &ProviderResolution) -> Uuid {
        let mut aliases = self.aliases.clone();
        aliases.sort_by_key(|alias| alias.id);
        let mut product_context = self.product_context.clone();
        product_context.sort_by(|a, b| (a.kind, &a.value).cmp(&(b.kind, &b.value)));
        product_context.dedup();
        let snapshot = serde_json::json!({
            "resolver": "provider-precedence-v1", "aliases": aliases,
            "component_provider": self.component_provider,
            "resolved_component": component, "product_context": product_context
        });
        Uuid::new_v5(&Uuid::NAMESPACE_OID, snapshot.to_string().as_bytes())
    }

    pub fn provider(&self, identity: &ProviderIdentity, source: &str) -> ProviderResolution {
        let mut diagnostics = Vec::new();
        let mut providers = std::collections::BTreeSet::new();
        if identity.unavailable {
            diagnostics.push("Provider attribution was not preserved during ingestion; re-ingest the source document to recover it.".into());
        }
        let mut fallback = std::collections::BTreeSet::new();
        for identifier in &identity.identifiers {
            let identifier = normalize_reference(identifier);
            let mapped = self
                .aliases
                .iter()
                .filter(|a| {
                    a.data
                        .aliases
                        .iter()
                        .any(|v| v.normalized().to_string() == identifier)
                })
                .map(|a| a.data.provider.trim_end_matches('/').to_string())
                .collect::<Vec<_>>();
            if mapped.is_empty() {
                if let Some(namespace) = identifier.strip_prefix("namespace:") {
                    fallback.insert(namespace.to_string());
                } else if identifier.starts_with("cve-org:") {
                    fallback.insert(identifier);
                }
            } else {
                providers.extend(mapped);
            }
        }
        if providers.is_empty() {
            providers = fallback;
        }
        let provider = if providers.len() == 1 {
            providers.into_iter().next()
        } else {
            if providers.len() > 1 {
                diagnostics
                    .push("Conflicting provider identifiers; no provider was selected.".into());
            } else if !identity.identifiers.is_empty() {
                diagnostics.push("Provider identifiers have no configured alias.".into());
            }
            None
        };
        ProviderResolution {
            provider,
            source: source.into(),
            identifiers: identity.identifiers.clone(),
            diagnostics,
        }
    }
}

pub fn normalize_reference(value: &str) -> String {
    value
        .parse::<ProviderAliasIdentifier>()
        .map(|identifier| identifier.normalized().to_string())
        .unwrap_or_else(|_| value.trim().trim_end_matches('/').to_string())
}

/// Matches the provider of an assertion against the provider of the component.
///
/// Names match only when at most one side resolved to a provider: two different resolved
/// providers outweigh an equal display name.
pub fn provider_match(
    component: &ProviderResolution,
    assertion: &ProviderResolution,
) -> Option<ProviderMatch> {
    if component.provider.is_some() && assertion.provider == component.provider {
        return Some(ProviderMatch::Provider);
    }
    if component.provider.is_some() && assertion.provider.is_some() {
        return None;
    }
    let names = |p: &ProviderResolution| {
        p.identifiers
            .iter()
            .filter(|id| id.starts_with("name:"))
            .map(|id| normalize_reference(id))
            .collect::<BTreeSet<_>>()
    };
    (!names(component).is_disjoint(&names(assertion))).then_some(ProviderMatch::Name)
}
