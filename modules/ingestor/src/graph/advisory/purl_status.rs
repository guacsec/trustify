use crate::graph::advisory::version::VersionInfo;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::{purl_status, status::Status, version_range};
use uuid::Uuid;

use sea_orm::Set;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0x50, 0xd5, 0xef, 0x1c, 0xd2, 0x38, 0x48, 0x2e, 0x9f, 0x4d, 0xf0, 0x44, 0x5e, 0x05, 0x59, 0x1f,
]);

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub struct PurlStatus {
    pub cpe: Option<Cpe>,
    pub purl: Purl,
    pub status: Status,
    pub info: VersionInfo,
}

impl PurlStatus {
    pub fn new(cpe: Option<Cpe>, purl: Purl, status: Status, info: VersionInfo) -> Self {
        Self {
            cpe,
            purl,
            status,
            info,
        }
    }

    pub fn into_active_model(
        self,
        advisory_id: Uuid,
        vulnerability_id: String,
    ) -> (version_range::ActiveModel, purl_status::ActiveModel) {
        let package_id = self.purl.package_uuid();
        let cpe_id = self.cpe.as_ref().map(Cpe::uuid);

        let version_range = self.info.clone().into_active_model();

        let package_status = purl_status::ActiveModel {
            id: Set(self.uuid(advisory_id, vulnerability_id.clone())),
            advisory_id: Set(advisory_id),
            vulnerability_id: Set(vulnerability_id),
            status: Set(self.status),
            base_purl_id: Set(package_id),
            context_cpe_id: Set(cpe_id),
            version_range_id: version_range.clone().id,
        };

        (version_range, package_status)
    }

    /// Compute a deterministic UUID for deduplication
    pub fn uuid(&self, advisory_id: Uuid, vulnerability_id: String) -> Uuid {
        let mut result = Uuid::new_v5(&NAMESPACE, self.status.to_string().as_bytes());
        result = Uuid::new_v5(&result, self.purl.package_uuid().as_bytes());
        result = Uuid::new_v5(&result, self.info.uuid().as_bytes());
        result = Uuid::new_v5(&result, advisory_id.as_bytes());
        result = Uuid::new_v5(&result, vulnerability_id.as_bytes());

        if let Some(cpe) = &self.cpe {
            result = Uuid::new_v5(&result, cpe.uuid().as_bytes())
        }

        result
    }
}
