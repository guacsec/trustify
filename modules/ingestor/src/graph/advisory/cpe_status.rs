use crate::graph::advisory::version::VersionInfo;
use trustify_common::cpe::Cpe;
use trustify_entity::{cpe_status, version_range};
use uuid::Uuid;

use sea_orm::Set;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0x8f, 0x3a, 0x6c, 0x02, 0x4b, 0x1d, 0x4a, 0x7e, 0xb1, 0x0c, 0x2d, 0x9a, 0x77, 0x4e, 0x1f, 0x63,
]);

/// A vulnerability status keyed by a CPE (vendor/product identity), mirroring
/// [`crate::graph::advisory::purl_status::PurlStatus`].
///
/// `cpe` carries the affected vendor/product identity with its version
/// component normalized to ANY (see [`Cpe::with_any_version`]); the actual
/// affected version(s) are expressed through `info` (a `version_range`).
#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub struct CpeStatus {
    pub cpe: Cpe,
    pub context_cpe: Option<Cpe>,
    pub status: Uuid,
    pub info: VersionInfo,
}

impl CpeStatus {
    pub fn new(cpe: Cpe, context_cpe: Option<Cpe>, status: Uuid, info: VersionInfo) -> Self {
        Self {
            cpe,
            context_cpe,
            status,
            info,
        }
    }

    pub fn into_active_model(
        self,
        advisory_id: Uuid,
        vulnerability_id: String,
    ) -> (version_range::ActiveModel, cpe_status::ActiveModel) {
        let cpe_id = self.cpe.uuid();
        let context_cpe_id = self.context_cpe.as_ref().map(Cpe::uuid);

        let version_range = self.info.clone().into_active_model();

        let cpe_status = cpe_status::ActiveModel {
            id: Set(self.uuid(advisory_id, vulnerability_id.clone())),
            advisory_id: Set(advisory_id),
            vulnerability_id: Set(vulnerability_id),
            status_id: Set(self.status),
            cpe_id: Set(cpe_id),
            context_cpe_id: Set(context_cpe_id),
            version_range_id: version_range.clone().id,
        };

        (version_range, cpe_status)
    }

    pub fn uuid(&self, advisory_id: Uuid, vulnerability_id: String) -> Uuid {
        let mut result = Uuid::new_v5(&NAMESPACE, self.status.as_bytes());
        result = Uuid::new_v5(&result, self.cpe.uuid().as_bytes());
        result = Uuid::new_v5(&result, self.info.uuid().as_bytes());
        result = Uuid::new_v5(&result, advisory_id.as_bytes());
        result = Uuid::new_v5(&result, vulnerability_id.as_bytes());

        if let Some(cpe) = &self.context_cpe {
            result = Uuid::new_v5(&result, cpe.uuid().as_bytes())
        }

        result
    }
}
