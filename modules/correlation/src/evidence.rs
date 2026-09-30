use crate::error::Error;
use sea_orm::{ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter};
use tracing::{Instrument, info_span};
use trustify_entity::{advisory_vulnerability_hash, advisory_vulnerability_product_identifier};

/// Load advisory_vulnerability_hash rows matching any of the given hash values.
pub async fn load_advisory_hashes_by_values<C: ConnectionTrait>(
    values: &[&str],
    connection: &C,
) -> Result<Vec<advisory_vulnerability_hash::Model>, Error> {
    let mut results = Vec::new();
    for chunk in values.chunks(5000) {
        let rows = advisory_vulnerability_hash::Entity::find()
            .filter(advisory_vulnerability_hash::Column::Value.is_in(chunk.iter().copied()))
            .all(connection)
            .instrument(info_span!("loading advisory hashes by value"))
            .await?;
        results.extend(rows);
    }
    Ok(results)
}

// ponytail: loads all wildcard rows globally; add boolean column/index if table grows large
/// Load advisory product identifier rows whose value contains CSAF glob wildcards.
pub async fn load_wildcard_product_identifiers<C: ConnectionTrait>(
    connection: &C,
) -> Result<Vec<advisory_vulnerability_product_identifier::Model>, Error> {
    Ok(advisory_vulnerability_product_identifier::Entity::find()
        .filter(
            Condition::any()
                .add(advisory_vulnerability_product_identifier::Column::Value.like("%*%"))
                .add(advisory_vulnerability_product_identifier::Column::Value.like("%?%")),
        )
        .all(connection)
        .instrument(info_span!("loading wildcard product identifiers"))
        .await?)
}

/// Load advisory_vulnerability_product_identifier rows matching any of the given values.
pub async fn load_product_identifiers_by_values<C: ConnectionTrait>(
    values: &[&str],
    connection: &C,
) -> Result<Vec<advisory_vulnerability_product_identifier::Model>, Error> {
    let mut results = Vec::new();
    for chunk in values.chunks(5000) {
        let rows = advisory_vulnerability_product_identifier::Entity::find()
            .filter(
                advisory_vulnerability_product_identifier::Column::Value
                    .is_in(chunk.iter().copied()),
            )
            .all(connection)
            .instrument(info_span!("loading product identifiers by value"))
            .await?;
        results.extend(rows);
    }
    Ok(results)
}
