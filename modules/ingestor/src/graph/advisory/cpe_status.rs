use crate::graph::advisory::version::VersionInfo;
use trustify_common::cpe::Cpe;
use trustify_entity::{cpe_status, status::Status, version_range};
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
    pub status: Status,
    pub info: VersionInfo,
}

impl CpeStatus {
    pub fn new(cpe: Cpe, context_cpe: Option<Cpe>, status: Status, info: VersionInfo) -> Self {
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
            status: Set(self.status),
            cpe_id: Set(cpe_id),
            context_cpe_id: Set(context_cpe_id),
            version_range_id: version_range.clone().id,
        };

        (version_range, cpe_status)
    }

    pub fn uuid(&self, advisory_id: Uuid, vulnerability_id: String) -> Uuid {
        cpe_status_id(
            &self.status.to_string(),
            self.cpe.uuid(),
            self.info.uuid(),
            advisory_id,
            &vulnerability_id,
            self.context_cpe.as_ref().map(Cpe::uuid),
        )
    }
}

/// Computes the deterministic v5 UUID primary key of a `cpe_status` row.
///
/// This is the single source of truth for that id: [`CpeStatus::uuid`] calls it
/// from the in-memory model, and the `m0002320_replace_status_with_enum`
/// migration calls it with the equivalent stored column values to recompute the
/// ids of existing rows in place. Every input is a persisted column, so a row's
/// id can always be reproduced from the row alone.
///
/// `status` is the status *slug* (e.g. `"affected"` — [`Status`]'s `Display`
/// form). The pre-enum implementation instead hashed the status *UUID* bytes;
/// switching to the slug is what makes the ids change and is why the migration
/// exists.
pub fn cpe_status_id(
    status: &str,
    cpe_id: Uuid,
    version_range_id: Uuid,
    advisory_id: Uuid,
    vulnerability_id: &str,
    context_cpe_id: Option<Uuid>,
) -> Uuid {
    let mut result = Uuid::new_v5(&NAMESPACE, status.as_bytes());
    result = Uuid::new_v5(&result, cpe_id.as_bytes());
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
    use super::cpe_status_id;
    use uuid::Uuid;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    const CPE_ID: u128 = 0x1111;
    const VRANGE: u128 = 0x2222;
    const ADVISORY: u128 = 0x3333;
    const CTX_CPE: u128 = 0x4444;

    fn id(status: &str, ctx_cpe: Option<Uuid>) -> Uuid {
        cpe_status_id(status, u(CPE_ID), u(VRANGE), u(ADVISORY), "CVE-1", ctx_cpe)
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(
            id("affected", Some(u(CTX_CPE))),
            id("affected", Some(u(CTX_CPE)))
        );
    }

    #[test]
    fn context_cpe_is_load_bearing() {
        assert_ne!(id("affected", None), id("affected", Some(u(CTX_CPE))));
    }

    #[test]
    fn every_input_changes_the_id() {
        let base = id("affected", None);
        assert_ne!(base, id("fixed", None));
        assert_ne!(
            base,
            cpe_status_id("affected", u(0xDEAD), u(VRANGE), u(ADVISORY), "CVE-1", None)
        );
        assert_ne!(
            base,
            cpe_status_id("affected", u(CPE_ID), u(0xDEAD), u(ADVISORY), "CVE-1", None)
        );
        assert_ne!(
            base,
            cpe_status_id("affected", u(CPE_ID), u(VRANGE), u(0xDEAD), "CVE-1", None)
        );
        assert_ne!(
            base,
            cpe_status_id("affected", u(CPE_ID), u(VRANGE), u(ADVISORY), "CVE-2", None)
        );
    }

    /// Golden value pinning the exact v5 chain. Changing it invalidates every
    /// stored id and the m0002320 recompute — update only deliberately.
    #[test]
    fn golden() {
        assert_eq!(
            id("affected", Some(u(CTX_CPE))),
            Uuid::from_u128(0x66bac70f_fedf_5879_a4af_ded8dffe3281)
        );
    }
}
