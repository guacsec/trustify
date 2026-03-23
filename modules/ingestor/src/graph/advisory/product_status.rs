use crate::graph::advisory::version::VersionInfo;
use trustify_common::cpe::Cpe;
use trustify_entity::{product_status, product_version_range, version_range};
use uuid::Uuid;

use sea_orm::Set;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0x59, 0x0c, 0x4b, 0xbb, 0x58, 0x96, 0x4a, 0xa6, 0xa4, 0xcc, 0x5c, 0x2d, 0x36, 0xb3, 0xe9, 0x6c,
]);

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub struct ProductVersionRange {
    pub cpe: Option<Cpe>,
    pub product_id: Uuid,
    pub info: VersionInfo,
}

impl ProductVersionRange {
    pub fn into_active_model(
        self,
    ) -> (
        version_range::ActiveModel,
        product_version_range::ActiveModel,
    ) {
        let version_range_entity = self.info.clone().into_active_model();

        let version_cpe_key = self
            .cpe
            .clone()
            .map(|cpe| cpe.version().as_ref().to_string());

        let product_version_range_entity = product_version_range::ActiveModel {
            id: Set(self.uuid()),
            product_id: Set(self.product_id),
            version_range_id: version_range_entity.id.clone(),
            cpe_key: Set(version_cpe_key),
        };

        (version_range_entity, product_version_range_entity)
    }

    pub fn uuid(&self) -> Uuid {
        let mut result = Uuid::new_v5(&NAMESPACE, self.product_id.as_bytes());
        result = Uuid::new_v5(&result, self.info.uuid().as_bytes());

        if let Some(cpe) = &self.cpe {
            result = Uuid::new_v5(&result, cpe.version().as_ref().as_bytes())
        }

        result
    }
}

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub struct ProductStatus {
    pub cpe: Option<Cpe>,
    pub package: Option<String>,
    pub status: Uuid,
    pub product_version_range_id: Uuid,
    pub csaf_product_ids: Option<Vec<String>>,
}

impl ProductStatus {
    pub fn into_active_model(
        self,
        advisory_id: Uuid,
        vulnerability_id: String,
    ) -> product_status::ActiveModel {
        product_status::ActiveModel {
            id: Set(self.uuid(advisory_id, vulnerability_id.clone())),
            advisory_id: Set(advisory_id),
            vulnerability_id: Set(vulnerability_id),
            status_id: Set(self.status),
            package: Set(self.package),
            context_cpe_id: Set(self.cpe.as_ref().map(Cpe::uuid)),
            product_version_range_id: Set(self.product_version_range_id),
            csaf_product_ids: Set(self.csaf_product_ids),
        }
    }

    pub fn uuid(&self, advisory_id: Uuid, vulnerability_id: String) -> Uuid {
        let mut result = Uuid::new_v5(&NAMESPACE, self.status.as_bytes());
        result = Uuid::new_v5(&result, self.product_version_range_id.as_bytes());
        result = Uuid::new_v5(&result, advisory_id.as_bytes());
        result = Uuid::new_v5(&result, vulnerability_id.as_bytes());

        if let Some(cpe) = &self.cpe {
            result = Uuid::new_v5(&result, cpe.uuid().as_bytes())
        }

        if let Some(package) = &self.package {
            result = Uuid::new_v5(&result, package.as_bytes())
        }

        result
    }
}
