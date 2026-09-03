use crate::graph::advisory::version::VersionInfo;
use trustify_common::cpe::Cpe;
use trustify_entity::{product_status, product_version_range, status::Status, version_range};
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
    pub status: Status,
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
            status: Set(self.status),
            package: Set(self.package),
            context_cpe_id: Set(self.cpe.as_ref().map(Cpe::uuid)),
            product_version_range_id: Set(self.product_version_range_id),
            csaf_product_ids: Set(self.csaf_product_ids),
        }
    }

    pub fn uuid(&self, advisory_id: Uuid, vulnerability_id: String) -> Uuid {
        product_status_id(
            &self.status.to_string(),
            self.product_version_range_id,
            advisory_id,
            &vulnerability_id,
            self.cpe.as_ref().map(Cpe::uuid),
            self.package.as_deref(),
        )
    }
}

/// Computes the deterministic v5 UUID primary key of a `product_status` row.
///
/// This is the single source of truth for that id: [`ProductStatus::uuid`] calls
/// it from the in-memory model, and the `m0002320_replace_status_with_enum`
/// migration calls it with the equivalent stored column values to recompute the
/// ids of existing rows in place. Every input is a persisted column, so a row's
/// id can always be reproduced from the row alone.
///
/// `status` is the status *slug* (e.g. `"affected"` — [`Status`]'s `Display`
/// form). The pre-enum implementation instead hashed the status *UUID* bytes;
/// switching to the slug is what makes the ids change and is why the migration
/// exists. The `context_cpe_id`-then-`package` order is load-bearing.
pub fn product_status_id(
    status: &str,
    product_version_range_id: Uuid,
    advisory_id: Uuid,
    vulnerability_id: &str,
    context_cpe_id: Option<Uuid>,
    package: Option<&str>,
) -> Uuid {
    let mut result = Uuid::new_v5(&NAMESPACE, status.as_bytes());
    result = Uuid::new_v5(&result, product_version_range_id.as_bytes());
    result = Uuid::new_v5(&result, advisory_id.as_bytes());
    result = Uuid::new_v5(&result, vulnerability_id.as_bytes());
    if let Some(context_cpe_id) = context_cpe_id {
        result = Uuid::new_v5(&result, context_cpe_id.as_bytes());
    }
    if let Some(package) = package {
        result = Uuid::new_v5(&result, package.as_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::product_status_id;
    use uuid::Uuid;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    const PVRANGE: u128 = 0x1111;
    const ADVISORY: u128 = 0x3333;
    const CPE: u128 = 0x4444;

    fn id(status: &str, ctx_cpe: Option<Uuid>, package: Option<&str>) -> Uuid {
        product_status_id(status, u(PVRANGE), u(ADVISORY), "CVE-1", ctx_cpe, package)
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(
            id("affected", Some(u(CPE)), Some("pkg")),
            id("affected", Some(u(CPE)), Some("pkg"))
        );
    }

    #[test]
    fn context_cpe_and_package_are_load_bearing() {
        // Each optional trailing link independently changes the id (both are read
        // as Option in the migration), and the two are not interchangeable: a
        // cpe-only row and a package-only row hash differently.
        assert_ne!(
            id("affected", None, None),
            id("affected", Some(u(CPE)), None)
        );
        assert_ne!(
            id("affected", None, None),
            id("affected", None, Some("pkg"))
        );
        assert_ne!(
            id("affected", Some(u(CPE)), None),
            id("affected", None, Some("pkg"))
        );
    }

    #[test]
    fn every_input_changes_the_id() {
        let base = id("affected", None, None);
        assert_ne!(base, id("fixed", None, None));
        assert_ne!(
            base,
            product_status_id("affected", u(0xDEAD), u(ADVISORY), "CVE-1", None, None)
        );
        assert_ne!(
            base,
            product_status_id("affected", u(PVRANGE), u(0xDEAD), "CVE-1", None, None)
        );
        assert_ne!(
            base,
            product_status_id("affected", u(PVRANGE), u(ADVISORY), "CVE-2", None, None)
        );
    }

    /// Golden value pinning the exact v5 chain. Changing it invalidates every
    /// stored id and the m0002320 recompute — update only deliberately.
    #[test]
    fn golden() {
        assert_eq!(
            id("affected", Some(u(CPE)), Some("pkg")),
            Uuid::from_u128(0xc33b1f3b_fb5f_5d86_af5d_37043b515008)
        );
    }
}
