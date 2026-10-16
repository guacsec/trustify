use super::provider::{ResolutionContext, normalize_reference};
use crate::{error::Error, extractor::context::format_cpe, model::*};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, EntityTrait, FromQueryResult,
    QueryFilter, Statement,
};
use std::collections::{HashMap, HashSet};
use trustify_entity::{advisory, organization, sbom, sbom_package};
use uuid::Uuid;

#[derive(FromQueryResult)]
struct AliasRow {
    id: Uuid,
    revision: Uuid,
    provider: String,
    aliases: serde_json::Value,
}

#[derive(Default)]
pub struct ProviderSnapshot {
    pub aliases: Vec<ProviderAlias>,
    suppliers: HashMap<(Uuid, String), ProviderIdentity>,
    products: HashMap<Uuid, ProviderIdentity>,
    pub advisory_providers: HashMap<Uuid, ProviderIdentity>,
}

impl ProviderSnapshot {
    pub async fn load(
        connection: &DatabaseTransaction,
        sboms: &[Uuid],
        advisories: &[Uuid],
    ) -> Result<Self, Error> {
        let mut result = Self {
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

    pub fn context(&self, request: &ResolutionRequest) -> Result<ResolutionContext, Error> {
        ResolutionContext::new(self.aliases.clone(), request)
    }

    pub fn component_provider(
        &self,
        sbom_id: Option<Uuid>,
        node_id: Option<&str>,
        identifiers: &[IdentifierRef],
        context: &ResolutionContext,
    ) -> ProviderResolution {
        if let Some(provider) = &context.component_provider {
            return ProviderResolution {
                provider: Some(provider.clone()),
                source: "request context".into(),
                ..Default::default()
            };
        }
        if let Some(identity) = sbom_id
            .zip(node_id)
            .and_then(|(sbom, node)| self.suppliers.get(&(sbom, node.into())))
        {
            return context.provider(identity, "component supplier");
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
                let resolved = context.provider(&identity, source);
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
            return context.provider(identity, "product supplier");
        }
        if !upstream_ids.is_empty() {
            let resolved = context.provider(
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
            "The SBOM states no supplier or other provider identifier for this component."
        } else {
            "Provider identifiers have no configured alias."
        };
        ProviderResolution {
            source: "unknown".into(),
            identifiers: tried,
            diagnostics: vec![diagnostic.into()],
            ..Default::default()
        }
    }
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

    #[test]
    fn supplier_identity_is_exact_and_unresolved_supplier_does_not_inherit() {
        let sbom = Uuid::new_v4();
        let mut snapshot = ProviderSnapshot::default();
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
        let context = ResolutionContext {
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
                .component_provider(Some(sbom), Some("component"), &[], &context)
                .provider,
            None
        );
        assert_eq!(
            snapshot
                .component_provider(Some(sbom), Some("inherited"), &[], &context)
                .provider
                .as_deref(),
            Some("A")
        );
        let cve = ProviderIdentity {
            identifiers: vec!["cve-org:example".into(), "name:Acme".into()],
            ..Default::default()
        };
        assert_eq!(
            context.provider(&cve, "assertion").provider.as_deref(),
            Some("A")
        );
        assert_eq!(normalize_reference("name:Organization: ACME"), "name:acme");
    }
}
