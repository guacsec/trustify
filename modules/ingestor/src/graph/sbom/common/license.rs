use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use spdx_expression::SpdxExpression;
use std::collections::BTreeMap;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::license;
use uuid::Uuid;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LicenseInfo {
    pub license: String,
}

impl LicenseInfo {
    pub fn uuid(&self) -> Uuid {
        // UUID based upon a hash of the lowercase de-ref'd license.
        Uuid::new_v5(&NAMESPACE, self.license.to_lowercase().as_bytes())
    }

    pub fn spdx_info(&self) -> (Vec<String>, Vec<String>) {
        SpdxExpression::parse(&self.license)
            .map(|parsed| {
                let spdx_licenses = parsed
                    .licenses()
                    .iter()
                    .filter(|e| !e.license_ref)
                    .map(|e| e.identifier.to_string())
                    .collect::<Vec<_>>();

                let spdx_license_exceptions = parsed
                    .exceptions()
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>();

                (spdx_licenses, spdx_license_exceptions)
            })
            .unwrap_or((vec![], vec![]))
    }
}

#[derive(Default, Debug, Clone)]
pub struct LicenseCreator {
    /// The licenses to create.
    ///
    /// Uses a [`BTreeMap`] to ensure we have a stable insertion order, avoiding deadlocks on the
    /// database.
    pub licenses: BTreeMap<Uuid, license::ActiveModel>,
}

impl LicenseCreator {
    pub fn new() -> Self {
        Self {
            licenses: Default::default(),
        }
    }

    pub fn add(&mut self, info: &LicenseInfo) {
        let uuid = info.uuid();

        let (spdx_licenses, spdx_exceptions) = info.spdx_info();

        self.licenses.entry(uuid).or_insert(license::ActiveModel {
            id: Set(uuid),
            text: Set(info.license.clone()),
            spdx_licenses: if spdx_licenses.is_empty() {
                Set(None)
            } else {
                Set(Some(spdx_licenses))
            },
            spdx_license_exceptions: if spdx_exceptions.is_empty() {
                Set(None)
            } else {
                Set(Some(spdx_exceptions))
            },
        });
    }

    #[instrument(skip_all, fields(num = self.licenses.len()), err(level=tracing::Level::INFO))]
    pub async fn create<C>(self, db: &C) -> Result<(), DbErr>
    where
        C: ConnectionTrait,
    {
        for batch in &self.licenses.into_values().chunked() {
            license::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([license::Column::Id])
                        .do_nothing()
                        .to_owned(),
                )
                .try_insert()
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::graph::sbom::LicenseInfo;

    #[test]
    fn stable_uuid() {
        // create a new license, ensure a new random state of the hashmap
        let license = || LicenseInfo {
            license: "LicenseRef-1-2-3".to_string(),
        };

        // the original one we compare to
        let original = license();

        for _ in 0..10 {
            // a new one, containing the same information
            let new = license();
            // should be equal
            assert_eq!(original, new);
            // and generate the same UUID
            assert_eq!(original.uuid(), new.uuid());
        }
    }
}
