use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_crypto")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    #[sea_orm(primary_key)]
    pub node_id: String,
    pub asset_type: CryptoAssetType,
    pub properties: serde_json::Value,
    pub oid: Option<String>,
}

/// Possible types of the cryptographic assets within a CBOM
/// https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties_assetType
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    serde::Serialize,
    serde::Deserialize,
    strum::EnumString,
    strum::Display,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "crypto_asset_type")]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum CryptoAssetType {
    /// Mathematical function commonly used for data encryption, authentication, and digital signatures.
    #[sea_orm(string_value = "algorithm")]
    Algorithm,
    /// An electronic document that is used to provide the identity or validate a public key.
    #[sea_orm(string_value = "certificate")]
    Certificate,
    /// A set of rules and guidelines that govern the behavior and communication with each other.
    #[sea_orm(string_value = "protocol")]
    Protocol,
    /// Other cryptographic assets related to algorithms, certificates, and protocols such as keys and tokens.
    #[sea_orm(string_value = "related-crypto-material")]
    RelatedCryptoMaterial,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_one = "super::sbom_node::Entity")]
    Node,
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(
        belongs_to = "super::sbom_package_purl_ref::Entity",
        from = "(Column::SbomId, Column::NodeId)",
        to = "(super::sbom_package_purl_ref::Column::SbomId, super::sbom_package_purl_ref::Column::NodeId)"
    )]
    Purl,
}

impl Related<super::sbom_node::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Node.def()
    }
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::sbom_package_purl_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Purl.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;
    use test_log::test;

    #[test]
    fn crypto_asset_types() {
        use CryptoAssetType::*;

        // The standard conversions
        for (s, t) in [
            ("algorithm", Algorithm),
            ("certificate", Certificate),
            ("protocol", Protocol),
            ("related-crypto-material", RelatedCryptoMaterial),
        ] {
            assert_eq!(CryptoAssetType::from_str(s), Ok(t));
            assert_eq!(t.to_string(), s);
            assert_eq!(json!(t), json!(s));
        }

        // Error handling
        assert!(CryptoAssetType::from_str("missing").is_err());
        assert_eq!(CryptoAssetType::from_str("aLgOrItHm"), Ok(Algorithm));
    }
}
