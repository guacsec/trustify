use super::engine::{EffectivePolicy, normalize_reference, validate_weights};
use crate::{error::Error, extractor::context::format_cpe, model::*};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, EntityTrait, FromQueryResult,
    QueryFilter, Statement,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use trustify_entity::{
    advisory, organization, sbom, sbom_group, sbom_group_assignment, sbom_package,
};
use uuid::Uuid;

#[derive(FromQueryResult)]
struct PolicyRow {
    id: Uuid,
    revision: Uuid,
    scope: serde_json::Value,
    priority: i32,
    weights: serde_json::Value,
}
#[derive(FromQueryResult)]
struct AliasRow {
    id: Uuid,
    revision: Uuid,
    provider: String,
    aliases: serde_json::Value,
}

#[derive(Default)]
pub struct PolicySnapshot {
    pub policies: Vec<WeightPolicy>,
    pub aliases: Vec<ProviderAlias>,
    groups: HashMap<Uuid, Option<Uuid>>,
    memberships: HashMap<Uuid, Vec<Uuid>>,
    suppliers: HashMap<(Uuid, String), ProviderIdentity>,
    products: HashMap<Uuid, ProviderIdentity>,
    pub advisory_providers: HashMap<Uuid, ProviderIdentity>,
}

impl PolicySnapshot {
    pub async fn load(
        connection: &DatabaseTransaction,
        sboms: &[Uuid],
        advisories: &[Uuid],
    ) -> Result<Self, Error> {
        let mut result = Self {
            policies: list_policies(connection).await?,
            aliases: list_aliases(connection).await?,
            ..Default::default()
        };
        if !sboms.is_empty() {
            for row in sbom_package::Entity::find()
                .filter(sbom_package::Column::SbomId.is_in(sboms.iter().copied()))
                .all(connection)
                .await?
            {
                if let Some(supplier) = row.supplier {
                    result.suppliers.insert(
                        (row.sbom_id, row.node_id),
                        serde_json::from_value(supplier).map_err(Error::MatchedValue)?,
                    );
                }
            }
            for row in sbom::Entity::find()
                .filter(sbom::Column::SbomId.is_in(sboms.iter().copied()))
                .all(connection)
                .await?
            {
                let names = row
                    .suppliers
                    .into_iter()
                    .filter(|v| !matches!(v.as_str(), "NOASSERTION" | "NONE"))
                    .map(|v| format!("name:{v}"))
                    .collect::<Vec<_>>();
                if !names.is_empty() {
                    result.products.insert(
                        row.sbom_id,
                        ProviderIdentity {
                            identifiers: names,
                            ..Default::default()
                        },
                    );
                }
            }
            // CycloneDX's describing component can name the product supplier independently
            // of metadata.supplier. SPDX also records describing-package suppliers here.
            use trustify_entity::{package_relates_to_package, relationship::Relationship};
            for relation in package_relates_to_package::Entity::find()
                .filter(package_relates_to_package::Column::SbomId.is_in(sboms.iter().copied()))
                .filter(
                    package_relates_to_package::Column::Relationship.eq(Relationship::Describes),
                )
                .all(connection)
                .await?
            {
                if let Some(identity) = result
                    .suppliers
                    .get(&(relation.sbom_id, relation.right_node_id))
                {
                    let product = result.products.entry(relation.sbom_id).or_default();
                    product
                        .identifiers
                        .extend(identity.identifiers.iter().cloned());
                    product.identifiers.sort();
                    product.identifiers.dedup();
                }
            }
            {
                for row in sbom_group::Entity::find().all(connection).await? {
                    result.groups.insert(row.id, row.parent);
                }
                for row in sbom_group_assignment::Entity::find()
                    .filter(sbom_group_assignment::Column::SbomId.is_in(sboms.iter().copied()))
                    .all(connection)
                    .await?
                {
                    result
                        .memberships
                        .entry(row.sbom_id)
                        .or_default()
                        .push(row.group_id);
                }
            }
        }
        if !advisories.is_empty() {
            let rows = advisory::Entity::find()
                .filter(advisory::Column::Id.is_in(advisories.iter().copied()))
                .all(connection)
                .await?;
            let issuers = rows
                .iter()
                .filter_map(|r| r.issuer_id)
                .collect::<HashSet<_>>();
            let issuers = organization::Entity::find()
                .filter(organization::Column::Id.is_in(issuers))
                .all(connection)
                .await?
                .into_iter()
                .map(|r| (r.id, r.name))
                .collect::<HashMap<_, _>>();
            for row in rows {
                let provider = if let Some(namespace) = row.publisher_namespace {
                    ProviderIdentity {
                        identifiers: vec![format!("namespace:{namespace}")],
                        ..Default::default()
                    }
                } else if row.labels.get("type").is_some_and(|v| v == "cve") {
                    ProviderIdentity {
                        unavailable: true,
                        ..Default::default()
                    }
                } else if let Some(name) = row.issuer_id.and_then(|id| issuers.get(&id)) {
                    ProviderIdentity {
                        identifiers: vec![format!("name:{name}")],
                        name: Some(name.clone()),
                        ..Default::default()
                    }
                } else {
                    ProviderIdentity::default()
                };
                result.advisory_providers.insert(row.id, provider);
            }
        }
        Ok(result)
    }

    fn group_depths(
        &self,
        sbom_id: Uuid,
        selected: Option<Uuid>,
    ) -> Result<HashMap<Uuid, usize>, Error> {
        let mut depths = HashMap::new();
        let members = self.memberships.get(&sbom_id).cloned().unwrap_or_default();
        if selected.is_some_and(|id| !members.contains(&id)) {
            return Err(Error::BadRequest(
                "Selected policy group is not assigned to this SBOM".into(),
            ));
        }
        for group in selected.map(|id| vec![id]).unwrap_or(members) {
            let mut chain = Vec::new();
            let mut current = Some(group);
            while let Some(id) = current {
                if chain.contains(&id) {
                    return Err(Error::BadRequest(
                        "SBOM group hierarchy contains a cycle".into(),
                    ));
                }
                chain.push(id);
                current = self.groups.get(&id).copied().flatten();
            }
            for (depth, id) in chain.into_iter().rev().enumerate() {
                depths
                    .entry(id)
                    .and_modify(|v: &mut usize| *v = (*v).max(depth))
                    .or_insert(depth);
            }
        }
        Ok(depths)
    }

    pub fn effective(
        &self,
        sbom_id: Option<Uuid>,
        node_id: Option<&str>,
        request: &ResolutionRequest,
    ) -> Result<EffectivePolicy, Error> {
        let mut effective = EffectivePolicy {
            aliases: self.aliases.clone(),
            ..Default::default()
        };
        let groups = sbom_id
            .map(|id| self.group_depths(id, request.group_id))
            .transpose()?
            .unwrap_or_default();
        let mut applicable = self
            .policies
            .iter()
            .filter_map(|p| {
                let rank = match &p.data.scope {
                    PolicyScope::Instance => (0, 0),
                    PolicyScope::Group { group_id } => (1, *groups.get(group_id)?),
                    PolicyScope::Sbom { sbom_id: id } if Some(*id) == sbom_id => (2, 0),
                    PolicyScope::Component {
                        sbom_id: id,
                        node_id: node,
                    } if Some(*id) == sbom_id && Some(node.as_str()) == node_id => (3, 0),
                    _ => return None,
                };
                Some((rank, p))
            })
            .collect::<Vec<_>>();
        applicable.sort_by_key(|(rank, p)| (*rank, p.data.priority, p.id));
        let mut seen = BTreeMap::<((u8, usize), i32, String), serde_json::Value>::new();
        for (rank, p) in applicable {
            let origin = SettingOrigin {
                source: p.data.scope.to_string(),
                policy_id: Some(p.id),
                revision: Some(p.revision),
                scope: Some(p.data.scope.clone()),
            };
            let mut patch = EffectivePolicy::default();
            patch.settings.clear();
            patch.apply(&p.data.weights, origin.clone())?;
            for (key, setting) in patch.settings {
                if let Some(previous) =
                    seen.insert((rank, p.data.priority, key.clone()), setting.value.clone())
                    && previous != setting.value
                {
                    return Err(Error::Conflict(format!(
                        "Conflicting group policies at the same priority for {key}; select a group"
                    )));
                }
            }
            effective.apply(&p.data.weights, origin)?;
        }
        effective.apply(
            &request.overrides,
            SettingOrigin {
                source: "request override".into(),
                ..Default::default()
            },
        )?;
        Ok(effective)
    }

    pub fn component_provider(
        &self,
        sbom_id: Option<Uuid>,
        node_id: Option<&str>,
        identifiers: &[IdentifierRef],
        policy: &EffectivePolicy,
    ) -> ProviderResolution {
        if let Some(provider) = policy
            .settings
            .get("component_provider")
            .and_then(|s| s.value.as_str())
        {
            return ProviderResolution {
                provider: Some(provider.trim_end_matches('/').into()),
                source: policy.settings["component_provider"].origin.source.clone(),
                ..Default::default()
            };
        }
        if let Some(identity) = sbom_id
            .zip(node_id)
            .and_then(|(sbom, node)| self.suppliers.get(&(sbom, node.into())))
        {
            return policy.provider(identity, "component supplier");
        }
        let mut distribution = Vec::new();
        let mut package_ids = Vec::new();
        let mut upstream_ids = Vec::new();
        for identifier in identifiers {
            if identifier.kind == IdentifierKind::Purl {
                if let Ok(purl) = identifier.value.parse::<trustify_common::purl::Purl>() {
                    if let Some(distro) = purl.qualifiers.get("distro") {
                        distribution.push(format!("distro:{distro}"));
                        distribution.push(format!(
                            "distro:{}",
                            distro.split('-').next().unwrap_or(distro)
                        ));
                    }
                    let base = purl.to_base().to_string();
                    if let Some(rest) = base.strip_prefix("pkg:")
                        && let Some((ty, names)) = rest.split_once('/')
                        && let Some((namespace, _)) = names.rsplit_once('/')
                    {
                        package_ids.push(format!("purl:{ty}/{namespace}"));
                    }
                }
            } else if identifier.kind == IdentifierKind::Cpe {
                // CPE vendor hints are only used through explicitly configured aliases.
                let vendor = if identifier.value.starts_with("cpe:2.3:") {
                    identifier.value.split(':').nth(3)
                } else {
                    identifier
                        .value
                        .strip_prefix("cpe:/")
                        .and_then(|v| v.split(':').nth(1))
                };
                if let Some(vendor) = vendor {
                    upstream_ids.push(format!("cpe-vendor:{vendor}"));
                }
            }
        }
        // Every identifier tried, so an unresolved component shows what an alias could map.
        let mut tried = distribution
            .iter()
            .chain(&package_ids)
            .chain(&upstream_ids)
            .cloned()
            .collect::<Vec<_>>();
        tried.sort();
        tried.dedup();
        for (ids, source) in [
            (distribution, "distribution/build mapping"),
            (package_ids, "package identifier mapping"),
        ] {
            if !ids.is_empty() {
                let identity = ProviderIdentity {
                    identifiers: ids,
                    ..Default::default()
                };
                let resolved = policy.provider(&identity, source);
                if resolved.provider.is_some()
                    || resolved
                        .diagnostics
                        .iter()
                        .any(|d| d.starts_with("Conflicting"))
                {
                    return resolved;
                }
            }
        }
        if let Some(identity) = sbom_id.and_then(|id| self.products.get(&id)) {
            return policy.provider(identity, "product supplier");
        }
        if !upstream_ids.is_empty() {
            let resolved = policy.provider(
                &ProviderIdentity {
                    identifiers: upstream_ids,
                    ..Default::default()
                },
                "upstream identifier mapping",
            );
            if resolved.provider.is_some() {
                return resolved;
            }
        }
        let diagnostic = if tried.is_empty() {
            "The SBOM states no supplier or other provider identifier for this component; providerless evidence receives the fallback boost."
        } else {
            "Provider identifiers have no configured alias; providerless evidence receives the fallback boost."
        };
        ProviderResolution {
            source: "unknown".into(),
            identifiers: tried,
            diagnostics: vec![diagnostic.into()],
            ..Default::default()
        }
    }
}

pub async fn list_policies(connection: &impl ConnectionTrait) -> Result<Vec<WeightPolicy>, Error> {
    PolicyRow::find_by_statement(Statement::from_string(
        DbBackend::Postgres,
        "SELECT id,revision,scope,priority,weights FROM correlation_weight_policy ORDER BY id"
            .to_string(),
    ))
    .all(connection)
    .await?
    .into_iter()
    .map(|r| {
        Ok(WeightPolicy {
            id: r.id,
            revision: r.revision,
            data: WeightPolicyData {
                scope: serde_json::from_value(r.scope).map_err(Error::MatchedValue)?,
                priority: r.priority,
                weights: serde_json::from_value(r.weights).map_err(Error::MatchedValue)?,
            },
        })
    })
    .collect()
}
pub async fn list_aliases(connection: &impl ConnectionTrait) -> Result<Vec<ProviderAlias>, Error> {
    AliasRow::find_by_statement(Statement::from_string(
        DbBackend::Postgres,
        "SELECT id,revision,provider,aliases FROM correlation_provider_alias ORDER BY id"
            .to_string(),
    ))
    .all(connection)
    .await?
    .into_iter()
    .map(|r| {
        Ok(ProviderAlias {
            id: r.id,
            revision: r.revision,
            data: ProviderAliasData {
                provider: r.provider,
                aliases: serde_json::from_value(r.aliases).map_err(Error::MatchedValue)?,
            },
        })
    })
    .collect()
}

pub async fn save_policy(
    id: Option<Uuid>,
    data: WeightPolicyData,
    connection: &DatabaseTransaction,
) -> Result<WeightPolicy, Error> {
    validate_weights(&data.weights)?;
    match &data.scope {
        PolicyScope::Instance => {}
        PolicyScope::Group { group_id } => {
            if sbom_group::Entity::find_by_id(*group_id)
                .one(connection)
                .await?
                .is_none()
            {
                return Err(Error::NotFound(group_id.to_string()));
            }
        }
        PolicyScope::Sbom { sbom_id } => {
            if sbom::Entity::find_by_id(*sbom_id)
                .one(connection)
                .await?
                .is_none()
            {
                return Err(Error::NotFound(sbom_id.to_string()));
            }
        }
        PolicyScope::Component { sbom_id, node_id } => {
            if sbom_package::Entity::find_by_id((*sbom_id, node_id.clone()))
                .one(connection)
                .await?
                .is_none()
            {
                return Err(Error::NotFound(node_id.clone()));
            }
        }
    }
    connection
        .execute_unprepared("LOCK TABLE correlation_weight_policy IN SHARE ROW EXCLUSIVE MODE")
        .await?;
    let existing = list_policies(connection).await?;
    if let Some(id) = id
        && !existing.iter().any(|p| p.id == id)
    {
        return Err(Error::NotFound(id.to_string()));
    }
    if existing
        .iter()
        .any(|p| Some(p.id) != id && p.data.scope == data.scope)
    {
        return Err(Error::Conflict(
            "A policy already exists for this scope".into(),
        ));
    }
    let result = WeightPolicy {
        id: id.unwrap_or_else(Uuid::now_v7),
        revision: Uuid::now_v7(),
        data,
    };
    let scope = serde_json::to_value(&result.data.scope).map_err(Error::MatchedValue)?;
    let weights = serde_json::to_value(&result.data.weights).map_err(Error::MatchedValue)?;
    connection.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,"INSERT INTO correlation_weight_policy(id,revision,scope,priority,weights) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET revision=$2,scope=$3,priority=$4,weights=$5",[result.id.into(),result.revision.into(),scope.into(),result.data.priority.into(),weights.into()])).await?;
    Ok(result)
}

pub async fn save_alias(
    id: Option<Uuid>,
    mut data: ProviderAliasData,
    connection: &DatabaseTransaction,
) -> Result<ProviderAlias, Error> {
    data.provider = data.provider.trim().trim_end_matches('/').into();
    data.aliases = data
        .aliases
        .iter()
        .map(|v| normalize_reference(v))
        .collect();
    data.aliases.sort();
    data.aliases.dedup();
    if data.provider.is_empty()
        || data.aliases.iter().any(String::is_empty)
        || data.aliases.is_empty()
    {
        return Err(Error::BadRequest(
            "Provider and aliases must not be empty".into(),
        ));
    }
    connection
        .execute_unprepared("LOCK TABLE correlation_provider_alias IN SHARE ROW EXCLUSIVE MODE")
        .await?;
    let existing = list_aliases(connection).await?;
    if let Some(id) = id
        && !existing.iter().any(|a| a.id == id)
    {
        return Err(Error::NotFound(id.to_string()));
    }
    if existing.iter().any(|a| {
        Some(a.id) != id
            && (a.data.provider == data.provider
                || a.data
                    .aliases
                    .iter()
                    .any(|alias| data.aliases.contains(&normalize_reference(alias))))
    }) {
        return Err(Error::Conflict(
            "Provider or alias already belongs to another mapping".into(),
        ));
    }
    let result = ProviderAlias {
        id: id.unwrap_or_else(Uuid::now_v7),
        revision: Uuid::now_v7(),
        data,
    };
    connection.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,"INSERT INTO correlation_provider_alias(id,revision,provider,aliases) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET revision=$2,provider=$3,aliases=$4",[result.id.into(),result.revision.into(),result.data.provider.clone().into(),serde_json::json!(result.data.aliases).into()])).await?;
    Ok(result)
}

pub async fn delete_policy(id: Uuid, connection: &impl ConnectionTrait) -> Result<(), Error> {
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM correlation_weight_policy WHERE id=$1",
            [id.into()],
        ))
        .await?;
    Ok(())
}
pub async fn delete_alias(id: Uuid, connection: &impl ConnectionTrait) -> Result<(), Error> {
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM correlation_provider_alias WHERE id=$1",
            [id.into()],
        ))
        .await?;
    Ok(())
}

/// Compact, batched identifier input needed to infer providers for verdict counts.
pub async fn provider_identifiers(
    connection: &DatabaseTransaction,
    sboms: &[Uuid],
) -> Result<HashMap<(Uuid, String), Vec<IdentifierRef>>, Error> {
    use trustify_entity::{cpe, qualified_purl, sbom_node_cpe_ref, sbom_node_purl_ref};
    let mut result = HashMap::<(Uuid, String), Vec<IdentifierRef>>::new();
    for chunk in sboms.chunks(1000) {
        for (node, purl) in sbom_node_purl_ref::Entity::find()
            .filter(sbom_node_purl_ref::Column::SbomId.is_in(chunk.iter().copied()))
            .find_also_related(qualified_purl::Entity)
            .all(connection)
            .await?
        {
            if let Some(purl) = purl {
                result
                    .entry((node.sbom_id, node.node_id))
                    .or_default()
                    .push(IdentifierRef {
                        kind: IdentifierKind::Purl,
                        value: trustify_common::purl::Purl::from(purl.purl).to_string(),
                    });
            }
        }
        for (node, cpe) in sbom_node_cpe_ref::Entity::find()
            .filter(sbom_node_cpe_ref::Column::SbomId.is_in(chunk.iter().copied()))
            .find_also_related(cpe::Entity)
            .all(connection)
            .await?
        {
            if let Some(cpe) = cpe {
                result
                    .entry((node.sbom_id, node.node_id))
                    .or_default()
                    .push(IdentifierRef {
                        kind: IdentifierKind::Cpe,
                        value: format_cpe(&cpe),
                    });
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(scope: PolicyScope, priority: i32, value: f64) -> WeightPolicy {
        WeightPolicy {
            id: Uuid::new_v4(),
            revision: Uuid::new_v4(),
            data: WeightPolicyData {
                scope,
                priority,
                weights: WeightOverrides {
                    direct: Some(value),
                    ..Default::default()
                },
            },
        }
    }

    #[test]
    fn group_conflicts_require_selection_and_priority_is_explicit() {
        let sbom = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mut snapshot = PolicySnapshot {
            groups: HashMap::from([(parent, None), (a, Some(parent)), (b, Some(parent))]),
            ..Default::default()
        };
        snapshot.memberships.insert(sbom, vec![b, a]);
        snapshot.policies = vec![
            policy(PolicyScope::Group { group_id: parent }, 100, 2.0),
            policy(PolicyScope::Group { group_id: a }, 0, 3.0),
            policy(PolicyScope::Group { group_id: b }, 0, 4.0),
        ];
        assert!(matches!(
            snapshot.effective(Some(sbom), None, &ResolutionRequest::default()),
            Err(Error::Conflict(_))
        ));
        let selected = ResolutionRequest {
            group_id: Some(a),
            ..Default::default()
        };
        assert_eq!(
            snapshot
                .effective(Some(sbom), None, &selected)
                .unwrap()
                .factor("direct")
                .multiplier,
            3.0
        );
        snapshot.policies[2].data.priority = 1;
        assert_eq!(
            snapshot
                .effective(Some(sbom), None, &ResolutionRequest::default())
                .unwrap()
                .factor("direct")
                .multiplier,
            4.0
        );
        snapshot.groups.insert(parent, Some(a));
        assert!(snapshot.effective(Some(sbom), None, &selected).is_err());
    }

    #[test]
    fn supplier_identity_is_exact_and_unresolved_supplier_does_not_inherit() {
        let sbom = Uuid::new_v4();
        let mut snapshot = PolicySnapshot::default();
        snapshot.products.insert(
            sbom,
            ProviderIdentity {
                identifiers: vec!["name:Acme".into()],
                ..Default::default()
            },
        );
        snapshot.suppliers.insert(
            (sbom, "component".into()),
            ProviderIdentity {
                identifiers: vec!["name:Acme Other".into()],
                ..Default::default()
            },
        );
        let policy = EffectivePolicy {
            aliases: vec![ProviderAlias {
                id: Uuid::nil(),
                revision: Uuid::nil(),
                data: ProviderAliasData {
                    provider: "A".into(),
                    aliases: vec!["name:Acme".into()],
                },
            }],
            ..Default::default()
        };
        assert_eq!(
            snapshot
                .component_provider(Some(sbom), Some("component"), &[], &policy)
                .provider,
            None
        );
        assert_eq!(
            snapshot
                .component_provider(Some(sbom), Some("inherited"), &[], &policy)
                .provider
                .as_deref(),
            Some("A")
        );
        let cve = ProviderIdentity {
            identifiers: vec!["cve-org:example".into(), "name:Acme".into()],
            ..Default::default()
        };
        assert_eq!(
            policy.provider(&cve, "assertion").provider.as_deref(),
            Some("A")
        );
        assert_eq!(normalize_reference("name:Organization: ACME"), "name:acme");
    }
}
