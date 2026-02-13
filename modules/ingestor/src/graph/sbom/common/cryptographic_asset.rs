use std::str::FromStr;

use crate::{
    graph::sbom::{Checksum, ReferenceSource, common::node::NodeCreator},
    service::Error,
};
use anyhow::anyhow;
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use serde_cyclonedx::cyclonedx::v_1_6::Component;
use serde_json::Value;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::sbom_crypto::{self, CryptoAssetType};
use uuid::Uuid;

pub struct Asset {
    pub asset_type: CryptoAssetType,
    pub oid: Option<String>,
    pub properties: Value,
}

impl TryFrom<&Component> for Asset {
    type Error = Error;
    fn try_from(c: &Component) -> Result<Self, Self::Error> {
        match &c.crypto_properties {
            Some(crypto) => {
                let asset_type = CryptoAssetType::from_str(&crypto.asset_type)
                    .map_err(|e| Error::InvalidContent(anyhow!(e)))?;
                let oid = crypto.oid.clone();
                let properties = match asset_type {
                    CryptoAssetType::Algorithm => {
                        serde_json::to_value(crypto.algorithm_properties.clone())?
                    }
                    CryptoAssetType::Certificate => {
                        serde_json::to_value(crypto.certificate_properties.clone())?
                    }
                    CryptoAssetType::Protocol => {
                        serde_json::to_value(crypto.protocol_properties.clone())?
                    }
                    CryptoAssetType::RelatedCryptoMaterial => {
                        serde_json::to_value(crypto.related_crypto_material_properties.clone())?
                    }
                };
                Ok(Asset {
                    asset_type,
                    oid,
                    properties,
                })
            }
            None => Err(Error::InvalidContent(anyhow!("Missing crypto properties"))),
        }
    }
}

pub struct CryptographicAssetCreator {
    sbom_id: Uuid,
    nodes: NodeCreator,
    models: Vec<sbom_crypto::ActiveModel>,
}

impl CryptographicAssetCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::new(sbom_id),
            models: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity: usize) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::with_capacity(sbom_id, capacity),
            models: Vec::with_capacity(capacity),
        }
    }

    pub fn add<I, C>(&mut self, node_id: String, name: String, checksums: I, asset: Asset)
    where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.nodes.add(node_id.clone(), name, checksums);
        self.models.push(sbom_crypto::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id),
            asset_type: Set(asset.asset_type),
            oid: Set(asset.oid),
            properties: Set(asset.properties),
        });
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        self.nodes.create(db).await?;

        for batch in &self.models.into_iter().chunked() {
            sbom_crypto::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_crypto::Column::SbomId, sbom_crypto::Column::NodeId])
                        .do_nothing()
                        .to_owned(),
                )
                .exec(db)
                .await?;
        }
        Ok(())
    }
}

impl<'a> ReferenceSource<'a> for CryptographicAssetCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes.references()
    }
}
