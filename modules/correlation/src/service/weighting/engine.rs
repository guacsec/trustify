use crate::{error::Error, model::*};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct DecisionEvidence {
    pub reference: String,
    pub advisory_id: Uuid,
    pub status: ApiAssertionStatus,
    pub confidence: f64,
    pub extractor: String,
    pub value: Option<MatchedValue>,
    pub provider: ProviderIdentity,
}

#[derive(Clone, Debug)]
pub struct EffectivePolicy {
    pub settings: BTreeMap<String, EffectiveSetting>,
    pub aliases: Vec<ProviderAlias>,
}

impl Default for EffectivePolicy {
    fn default() -> Self {
        let settings = [
            ("matching_provider", 2.0),
            ("providerless", 1.0),
            ("providerless_fallback", 2.0),
            ("other_provider", 0.5),
            ("direct", 1.25),
            ("inferred", 1.0),
            ("conflict_sensitivity", 0.5),
        ]
        .into_iter()
        .map(|(key, value)| {
            (
                key.into(),
                EffectiveSetting {
                    value: serde_json::json!(value),
                    origin: SettingOrigin {
                        source: "default".into(),
                        ..Default::default()
                    },
                },
            )
        })
        .collect();
        Self {
            settings,
            aliases: Vec::new(),
        }
    }
}

impl EffectivePolicy {
    pub fn apply(&mut self, patch: &WeightOverrides, origin: SettingOrigin) -> Result<(), Error> {
        validate_weights(patch)?;
        let values = serde_json::to_value(patch).map_err(Error::MatchedValue)?;
        for (key, value) in values.as_object().into_iter().flatten() {
            if value.is_null() {
                continue;
            }
            if let Some(entries) = value.as_object() {
                for (entry, value) in entries {
                    let entry = if key == "providers" {
                        entry.trim().trim_end_matches('/')
                    } else {
                        entry.as_str()
                    };
                    self.settings.insert(
                        format!("{key}.{entry}"),
                        EffectiveSetting {
                            value: value.clone(),
                            origin: origin.clone(),
                        },
                    );
                }
            } else {
                self.settings.insert(
                    key.clone(),
                    EffectiveSetting {
                        value: if key == "component_provider" {
                            serde_json::json!(
                                value
                                    .as_str()
                                    .unwrap_or_default()
                                    .trim()
                                    .trim_end_matches('/')
                            )
                        } else {
                            value.clone()
                        },
                        origin: origin.clone(),
                    },
                );
            }
        }
        Ok(())
    }

    pub fn factor(&self, name: &str) -> AppliedWeight {
        match self.settings.get(name) {
            Some(setting) => AppliedWeight {
                factor: name.into(),
                multiplier: setting.value.as_f64().unwrap_or(1.0),
                origin: setting.origin.clone(),
            },
            None => AppliedWeight {
                factor: name.into(),
                multiplier: 1.0,
                origin: SettingOrigin {
                    source: "default".into(),
                    ..Default::default()
                },
            },
        }
    }

    pub fn revision(&self) -> Uuid {
        // BTreeMap and the sorted alias list keep fingerprints independent of DB row order.
        let mut aliases = self.aliases.clone();
        aliases.sort_by_key(|alias| alias.id);
        let snapshot = serde_json::json!({ "settings": self.settings, "aliases": aliases });
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
                        .any(|v| normalize_reference(v) == identifier)
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
    let value = value.trim();
    if let Some(name) = value.strip_prefix("name:") {
        format!(
            "name:{}",
            name.trim()
                .strip_prefix("Organization:")
                .unwrap_or(name)
                .trim()
                .to_lowercase()
        )
    } else {
        value.trim_end_matches('/').to_string()
    }
}

pub fn validate_weights(patch: &WeightOverrides) -> Result<(), Error> {
    for (key, value) in [
        ("matching_provider", patch.matching_provider),
        ("providerless", patch.providerless),
        ("providerless_fallback", patch.providerless_fallback),
        ("other_provider", patch.other_provider),
        ("direct", patch.direct),
        ("inferred", patch.inferred),
        ("conflict_sensitivity", patch.conflict_sensitivity),
    ] {
        if value.is_some_and(|v| !v.is_finite()) {
            return Err(Error::BadRequest(format!("{key} must be finite")));
        }
    }
    let value = serde_json::to_value(patch).map_err(Error::MatchedValue)?;
    for (key, value) in value.as_object().into_iter().flatten() {
        if key == "component_provider" {
            if value
                .as_str()
                .is_some_and(|v| v.trim().trim_end_matches('/').is_empty())
            {
                return Err(Error::BadRequest(
                    "component_provider must not be empty".into(),
                ));
            }
            continue;
        }
        let entries = if let Some(map) = value.as_object() {
            if map.keys().any(|key| key.trim().is_empty()) {
                return Err(Error::BadRequest(
                    "Multiplier keys must not be empty".into(),
                ));
            }
            if key == "providers" {
                let normalized = map
                    .keys()
                    .map(|v| v.trim().trim_end_matches('/'))
                    .collect::<std::collections::BTreeSet<_>>();
                if normalized.len() != map.len() || normalized.contains("") {
                    return Err(Error::BadRequest(
                        "Provider multiplier keys must be unique after normalization".into(),
                    ));
                }
            }
            map.values().collect::<Vec<_>>()
        } else if value.is_null() {
            Vec::new()
        } else {
            vec![value]
        };
        for value in entries {
            let number = value.as_f64().ok_or_else(|| {
                Error::BadRequest(format!("{key} must contain numeric multipliers"))
            })?;
            if !number.is_finite()
                || number < 0.0
                || (key == "conflict_sensitivity" && number >= 1.0)
            {
                return Err(Error::BadRequest(format!(
                    "{key} must be finite and nonnegative; conflict_sensitivity must be below 1"
                )));
            }
        }
    }
    Ok(())
}

fn status(status: ApiAssertionStatus) -> Option<VerdictStatus> {
    match status {
        ApiAssertionStatus::Affected => Some(VerdictStatus::Affected),
        ApiAssertionStatus::Fixed => Some(VerdictStatus::Fixed),
        ApiAssertionStatus::NotAffected => Some(VerdictStatus::NotAffected),
        ApiAssertionStatus::UnderInvestigation => Some(VerdictStatus::UnderInvestigation),
        ApiAssertionStatus::Recommended => None,
    }
}

fn priority(status: VerdictStatus) -> u8 {
    match status {
        VerdictStatus::Affected => 0,
        VerdictStatus::Fixed => 1,
        VerdictStatus::NotAffected => 2,
        VerdictStatus::UnderInvestigation => 3,
        VerdictStatus::None => 4,
    }
}

fn method(evidence: &DecisionEvidence) -> &str {
    // Rule IDs identify the strategy family; they do not determine status precedence.
    if let Some(value) = &evidence.value {
        if value.identifier.starts_with("pkg:") {
            return "purl";
        }
        if value.identifier.starts_with("cpe:") {
            return "cpe";
        }
    }
    evidence
        .extractor
        .strip_prefix("purl_")
        .map(|_| "purl")
        .unwrap_or(&evidence.extractor)
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub status: VerdictStatus,
    pub summary: ResolutionSummary,
    pub winning_advisory: Option<Uuid>,
}

pub fn resolve(
    evidence: &[DecisionEvidence],
    component: ProviderResolution,
    policy: &EffectivePolicy,
    explain: bool,
) -> Result<Decision, Error> {
    let providers = evidence
        .iter()
        .map(|e| policy.provider(&e.provider, "assertion source"))
        .collect::<Vec<_>>();
    let strength =
        |e: &DecisionEvidence| match e.value.as_ref().map(|v| v.origin).unwrap_or_default() {
            AssertionOrigin::Stated | AssertionOrigin::Default => "direct",
            _ => "inferred",
        };
    let factors = |e: &DecisionEvidence, provider: &ProviderResolution| {
        let provider_key = provider.provider.as_deref().unwrap_or("unidentified");
        vec![
            policy.factor(&format!("providers.{provider_key}")),
            policy.factor(strength(e)),
            policy.factor(&format!("match_methods.{}", method(e))),
            policy.factor(&format!("rules.{}", e.extractor)),
        ]
    };
    let matching_available = component.provider.is_some()
        && evidence.iter().zip(&providers).any(|(e, p)| {
            status(e.status).is_some()
                && p.provider == component.provider
                && e.confidence > 0.0
                && policy.factor("matching_provider").multiplier > 0.0
                && (e.confidence
                    * policy.factor("matching_provider").multiplier
                    * factors(e, p).iter().map(|f| f.multiplier).product::<f64>()
                    * 1_000_000.0)
                    .round()
                    > 0.0
        });
    let mut details = Vec::new();
    let mut best = BTreeMap::<u8, (VerdictStatus, usize)>::new();
    for (e, provider) in evidence.iter().zip(providers) {
        let relation = if component.provider.is_some() && provider.provider == component.provider {
            "matching_provider"
        } else if e.provider.identifiers.is_empty() && !e.provider.unavailable {
            if matching_available {
                "providerless"
            } else {
                "providerless_fallback"
            }
        } else {
            "other_provider"
        };
        let mut applied = vec![policy.factor(relation)];
        applied.extend(factors(e, &provider));
        let raw = e.confidence * applied.iter().map(|f| f.multiplier).product::<f64>();
        if !raw.is_finite() || !(0.0..=1.0).contains(&e.confidence) {
            return Err(Error::BadRequest(
                "Evidence confidence or the product of weighting factors is invalid".into(),
            ));
        }
        let weight = if status(e.status).is_some() {
            (raw * 1_000_000.0).round() / 1_000_000.0
        } else {
            0.0
        };
        if !weight.is_finite() {
            return Err(Error::BadRequest(
                "Weighting factors overflow the decision weight".into(),
            ));
        }
        let index = details.len();
        details.push(EvidenceWeight {
            evidence_ref: e.reference.clone(),
            advisory_id: e.advisory_id,
            status: e.status,
            match_confidence: e.confidence,
            assertion_origin: e.value.as_ref().map(|v| v.origin).unwrap_or_default(),
            provider,
            factors: applied,
            weight,
        });
        if let Some(status) = status(e.status).filter(|_| weight > 0.0) {
            let entry = best.entry(priority(status)).or_insert((status, index));
            let old = &details[entry.1];
            if weight > old.weight
                || (weight == old.weight
                    && (e.confidence > old.match_confidence
                        || (e.confidence == old.match_confidence
                            && e.reference < old.evidence_ref)))
            {
                *entry = (status, index);
            }
        }
    }
    let mut ranked = best.values().copied().collect::<Vec<_>>();
    ranked.sort_by(|a, b| {
        details[b.1]
            .weight
            .total_cmp(&details[a.1].weight)
            .then(priority(a.0).cmp(&priority(b.0)))
    });
    let winner = ranked.first().copied();
    let opposition = ranked.get(1).copied();
    let decision_weight = winner.map(|(_, i)| details[i].weight).unwrap_or(0.0);
    let base = winner
        .map(|(_, i)| details[i].match_confidence)
        .unwrap_or(0.0);
    let opposing_weight = opposition.map(|(_, i)| details[i].weight).unwrap_or(0.0);
    let penalty = if decision_weight > 0.0 {
        base * policy.factor("conflict_sensitivity").multiplier * opposing_weight / decision_weight
    } else {
        0.0
    };
    let verdict = winner.map(|(s, _)| s).unwrap_or(VerdictStatus::None);
    let tie_break = winner.is_some() && opposition.is_some() && decision_weight == opposing_weight;
    let winning_advisory = winner.map(|(_, i)| details[i].advisory_id);
    let explanation = explain.then(|| ResolutionExplanation {
        component_provider: component,
        policy_revision: policy.revision(),
        settings: policy.settings.clone(),
        statuses: ranked
            .iter()
            .map(|(s, i)| StatusWeight {
                status: *s,
                weight: details[*i].weight,
                evidence_ref: details[*i].evidence_ref.clone(),
            })
            .collect(),
        winning_evidence: winner.map(|(_, i)| details[i].evidence_ref.clone()),
        opposing_evidence: opposition.map(|(_, i)| details[i].evidence_ref.clone()),
        opposing_weight,
        base_confidence: base,
        confidence_penalty: penalty,
        tie_break,
        reason: if tie_break {
            "Equal decision weights; status priority breaks the tie (affected first).".into()
        } else if winner.is_some() {
            "The strongest applicable evidence has the highest decision weight.".into()
        } else {
            "No positive-weight voting evidence.".into()
        },
        evidence: {
            details.sort_by(|a, b| a.evidence_ref.cmp(&b.evidence_ref));
            details
        },
    });
    Ok(Decision {
        status: verdict,
        summary: ResolutionSummary {
            decision_weight,
            confidence: base - penalty,
            has_conflict: opposition.is_some(),
            explanation,
        },
        winning_advisory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence(
        id: &str,
        status: ApiAssertionStatus,
        confidence: f64,
        origin: AssertionOrigin,
        provider: Option<&str>,
    ) -> DecisionEvidence {
        DecisionEvidence {
            reference: id.into(),
            advisory_id: Uuid::nil(),
            status,
            confidence,
            extractor: "purl".into(),
            value: Some(MatchedValue {
                origin,
                ..MatchedValue::new("pkg:rpm/example/pkg")
            }),
            provider: ProviderIdentity {
                identifiers: provider
                    .map(|p| vec![format!("namespace:{p}")])
                    .unwrap_or_default(),
                ..Default::default()
            },
        }
    }
    fn component() -> ProviderResolution {
        ProviderResolution {
            provider: Some("A".into()),
            ..Default::default()
        }
    }
    #[test]
    fn provider_boost_is_soft_and_regressions_are_general() {
        let policy = EffectivePolicy::default();
        let fix = evidence(
            "fix",
            ApiAssertionStatus::Fixed,
            0.9,
            AssertionOrigin::PublisherPolicy,
            Some("A"),
        );
        let affected = evidence(
            "affected",
            ApiAssertionStatus::Affected,
            1.0,
            AssertionOrigin::Stated,
            None,
        );
        assert_eq!(
            resolve(
                &[fix.clone(), affected.clone()],
                component(),
                &policy,
                false
            )
            .unwrap()
            .status,
            VerdictStatus::Fixed
        );
        let weak = DecisionEvidence {
            confidence: 0.2,
            ..fix.clone()
        };
        assert_eq!(
            resolve(&[weak, affected], component(), &policy, false)
                .unwrap()
                .status,
            VerdictStatus::Affected
        );
        let regression = evidence(
            "regression",
            ApiAssertionStatus::Affected,
            1.0,
            AssertionOrigin::Stated,
            Some("A"),
        );
        assert_eq!(
            resolve(&[fix, regression], component(), &policy, false)
                .unwrap()
                .status,
            VerdictStatus::Affected
        );
    }
    #[test]
    fn ties_conflicts_duplicates_and_explanations() {
        let policy = EffectivePolicy::default();
        let a = evidence(
            "a",
            ApiAssertionStatus::Affected,
            0.8,
            AssertionOrigin::Stated,
            Some("A"),
        );
        let f = evidence(
            "f",
            ApiAssertionStatus::Fixed,
            0.8,
            AssertionOrigin::Stated,
            Some("A"),
        );
        let input = vec![f.clone(), a.clone(), f, a];
        let decision = resolve(&input, component(), &policy, true).unwrap();
        let status = decision.status;
        let result = &decision.summary;
        assert_eq!(status, VerdictStatus::Affected);
        assert_eq!(result.confidence, 0.4);
        assert!(result.has_conflict);
        assert!(result.explanation.as_ref().unwrap().tie_break);
        let mut reversed = input.clone();
        reversed.reverse();
        assert_eq!(
            resolve(&reversed, component(), &policy, true).unwrap(),
            decision.clone()
        );
        let plain = resolve(&input, component(), &policy, false)
            .unwrap()
            .summary;
        assert_eq!(plain.confidence, result.confidence);
        assert!(plain.explanation.is_none());
    }
    #[test]
    fn overrides_replace_and_zero_disables() {
        let mut policy = EffectivePolicy::default();
        policy
            .apply(
                &WeightOverrides {
                    matching_provider: Some(1.5),
                    ..Default::default()
                },
                SettingOrigin {
                    source: "component".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(policy.factor("matching_provider").multiplier, 1.5);
        policy
            .apply(
                &WeightOverrides {
                    rules: BTreeMap::from([("purl".into(), 0.0)]),
                    ..Default::default()
                },
                SettingOrigin::default(),
            )
            .unwrap();
        assert_eq!(
            resolve(
                &[evidence(
                    "a",
                    ApiAssertionStatus::Affected,
                    1.0,
                    AssertionOrigin::Stated,
                    Some("A")
                )],
                component(),
                &policy,
                true
            )
            .unwrap()
            .status,
            VerdictStatus::None
        );
        assert!(
            validate_weights(&WeightOverrides {
                conflict_sensitivity: Some(1.0),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            validate_weights(&WeightOverrides {
                direct: Some(-1.0),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            validate_weights(&WeightOverrides {
                direct: Some(f64::NAN),
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn fallback_does_not_treat_lost_metadata_as_generic() {
        let policy = EffectivePolicy::default();
        let generic = evidence(
            "generic",
            ApiAssertionStatus::Affected,
            1.0,
            AssertionOrigin::Stated,
            None,
        );
        let foreign = evidence(
            "foreign",
            ApiAssertionStatus::Fixed,
            1.0,
            AssertionOrigin::Stated,
            Some("B"),
        );
        let decision = resolve(&[generic.clone(), foreign], component(), &policy, true).unwrap();
        assert_eq!(decision.status, VerdictStatus::Affected);
        assert_eq!(decision.summary.decision_weight, 2.5);
        assert!(decision.summary.has_conflict);
        let lost = DecisionEvidence {
            provider: ProviderIdentity {
                unavailable: true,
                ..Default::default()
            },
            ..generic
        };
        let result = resolve(&[lost], component(), &policy, true).unwrap();
        assert_eq!(result.summary.decision_weight, 0.625);
        assert!(
            !result.summary.explanation.unwrap().evidence[0]
                .provider
                .diagnostics
                .is_empty()
        );
    }
}
