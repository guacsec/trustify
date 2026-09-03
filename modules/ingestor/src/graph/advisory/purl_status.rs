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

    pub fn uuid(&self, advisory_id: Uuid, vulnerability_id: String) -> Uuid {
        purl_status_id(
            &self.status.to_string(),
            self.purl.package_uuid(),
            self.info.uuid(),
            advisory_id,
            &vulnerability_id,
            self.cpe.as_ref().map(Cpe::uuid),
        )
    }
}

/// Computes the deterministic v5 UUID primary key of a `purl_status` row.
///
/// This is the single source of truth for that id: [`PurlStatus::uuid`] calls it
/// from the in-memory model, and the `m0002320_replace_status_with_enum`
/// migration calls it with the equivalent stored column values to recompute the
/// ids of existing rows in place. Every input is a persisted column, so a row's
/// id can always be reproduced from the row alone.
///
/// `status` is the status *slug* (e.g. `"affected"` — [`Status`]'s `Display`
/// form). The pre-enum implementation instead hashed the status *UUID* bytes;
/// switching to the slug is what makes the ids change and is why the migration
/// exists.
pub fn purl_status_id(
    status: &str,
    base_purl_id: Uuid,
    version_range_id: Uuid,
    advisory_id: Uuid,
    vulnerability_id: &str,
    context_cpe_id: Option<Uuid>,
) -> Uuid {
    let mut result = Uuid::new_v5(&NAMESPACE, status.as_bytes());
    result = Uuid::new_v5(&result, base_purl_id.as_bytes());
    result = Uuid::new_v5(&result, version_range_id.as_bytes());
    result = Uuid::new_v5(&result, advisory_id.as_bytes());
    result = Uuid::new_v5(&result, vulnerability_id.as_bytes());
    if let Some(context_cpe_id) = context_cpe_id {
        result = Uuid::new_v5(&result, context_cpe_id.as_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::purl_status_id;
    use uuid::Uuid;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    const BASE_PURL: u128 = 0x1111;
    const VRANGE: u128 = 0x2222;
    const ADVISORY: u128 = 0x3333;
    const CPE: u128 = 0x4444;

    fn id(status: &str, ctx_cpe: Option<Uuid>) -> Uuid {
        purl_status_id(
            status,
            u(BASE_PURL),
            u(VRANGE),
            u(ADVISORY),
            "CVE-1",
            ctx_cpe,
        )
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(id("affected", Some(u(CPE))), id("affected", Some(u(CPE))));
    }

    #[test]
    fn context_cpe_is_load_bearing() {
        // The optional trailing link must change the id — the migration reads
        // context_cpe_id as Option<Uuid>, so NULL vs present must not collide.
        assert_ne!(id("affected", None), id("affected", Some(u(CPE))));
    }

    #[test]
    fn every_input_changes_the_id() {
        let base = id("affected", None);
        assert_ne!(base, id("fixed", None));
        assert_ne!(
            base,
            purl_status_id("affected", u(0xDEAD), u(VRANGE), u(ADVISORY), "CVE-1", None)
        );
        assert_ne!(
            base,
            purl_status_id(
                "affected",
                u(BASE_PURL),
                u(0xDEAD),
                u(ADVISORY),
                "CVE-1",
                None
            )
        );
        assert_ne!(
            base,
            purl_status_id(
                "affected",
                u(BASE_PURL),
                u(VRANGE),
                u(0xDEAD),
                "CVE-1",
                None
            )
        );
        assert_ne!(
            base,
            purl_status_id(
                "affected",
                u(BASE_PURL),
                u(VRANGE),
                u(ADVISORY),
                "CVE-2",
                None
            )
        );
    }

    /// Golden value pinning the exact v5 chain. Changing it invalidates every
    /// stored id and the m0002320 recompute — update only deliberately.
    #[test]
    fn golden() {
        assert_eq!(
            id("affected", Some(u(CPE))),
            Uuid::from_u128(0xcec49799_4be0_56c1_b48c_f3a12f7a37fc)
        );
    }
}
