use crate::{Error, common::LicenseRefMapping, source_document::model::SourceDocument};
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, PaginatorTrait, Statement};
use spdx_expression;
use std::collections::BTreeMap;
use trustify_module_storage::service::{StorageBackend, StorageKey, dispatch::DispatchBackend};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum DocumentType {
    Advisory,
    Sbom,
}

/// Fetch all unique key/value labels matching the `filter_text` for all the `r#type` entities, i.e. `DocumentType::Advisory` or `DocumentType::Sbom`
///
/// If limit=0 then all data will be fetched
pub async fn fetch_labels<C: ConnectionTrait>(
    r#type: DocumentType,
    filter_text: String,
    limit: u64,
    connection: &C,
) -> Result<Vec<serde_json::Value>, Error> {
    let sql = format!(
        r#"
SELECT DISTINCT ON (kv.key, kv.value)
    kv.key,
    CASE
        WHEN kv.value IS NULL OR kv.value = '' THEN NULL
        ELSE kv.value
    END AS value
FROM {table},
    LATERAL jsonb_each_text(labels) AS kv
WHERE
    CASE
        WHEN kv.value IS NULL THEN kv.key
        ELSE kv.key || '=' || kv.value
    END ILIKE $1 ESCAPE '\'
ORDER BY
    kv.key, kv.value
"#,
        table = match r#type {
            DocumentType::Advisory => "advisory",
            DocumentType::Sbom => "sbom",
        }
    );

    let statement = Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        [format!("%{}%", escape(filter_text)).into()],
    );

    let selector = serde_json::Value::find_by_statement(statement);
    let labels: Vec<serde_json::Value> = if limit == 0 {
        selector.all(connection).await?
    } else {
        selector.paginate(connection, limit).fetch().await?
    };

    Ok(labels)
}

fn escape(text: String) -> String {
    text.replace('%', "\\").replace('\\', "\\\\")
}

/// Delete the original raw json doc from storage. An appropriate
/// message is returned in the event of an error, but it's up to the
/// caller to either log the message or return failure to its caller.
pub async fn delete_doc(doc: &SourceDocument, storage: impl DocumentDelete) -> Result<(), Error> {
    let key = doc.try_into()?;
    storage.delete(key).await
}

pub trait DocumentDelete {
    fn delete(&self, key: StorageKey) -> impl Future<Output = Result<(), Error>>;
}

impl DocumentDelete for &DispatchBackend {
    async fn delete(&self, key: StorageKey) -> Result<(), Error> {
        (*self).delete(key).await.map_err(Error::Storage)
    }
}

/// Extract LicenseRef mappings from SPDX license expressions
///
/// This function parses SPDX license expressions and extracts LicenseRef mappings,
/// which are then added to the provided `licenses_ref_mapping` vector.
///
/// # Arguments
/// * `license_name` - The SPDX license expression to parse
/// * `licensing_infos` - A BTreeMap containing license ID to license name mappings
/// * `licenses_ref_mapping` - A mutable vector where LicenseRef mappings will be added
pub fn extract_license_ref_mappings(
    license_name: &str,
    licensing_infos: &BTreeMap<String, String>,
    licenses_ref_mapping: &mut Vec<LicenseRefMapping>,
) {
    if let Ok(parsed) = spdx_expression::SpdxExpression::parse(license_name) {
        parsed
            .licenses()
            .into_iter()
            .filter(|license| license.license_ref)
            .for_each(|license| {
                let license_id = license.to_string();
                let license_name = licensing_infos
                    .get(&license_id)
                    .cloned()
                    .unwrap_or_default();
                licenses_ref_mapping.push(LicenseRefMapping {
                    license_id,
                    license_name,
                });
            });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::anyhow;
    use test_log::test;
    use trustify_module_storage::service::StorageKey;

    #[test(tokio::test)]
    async fn delete_failure() -> Result<(), anyhow::Error> {
        // Setup mock that simulates a delete error
        struct FailingDelete {}
        impl DocumentDelete for FailingDelete {
            async fn delete(&self, _key: StorageKey) -> Result<(), Error> {
                Err(Error::Storage(anyhow!("Delete failed")))
            }
        }

        // Failing to delete an invalid doc from storage should log an error
        let doc = SourceDocument::default();
        match delete_doc(&doc, FailingDelete {}).await {
            Ok(_) => panic!("expected error"),
            Err(e) => assert!(e.to_string().contains("Missing prefix")),
        };

        // Failing to delete a valid doc from storage should log a different error
        let doc = SourceDocument {
            sha256: String::from(
                "sha256:488c5d97daed3613746f0c246f4a3d1b26ea52ce43d6bdd33f4219f881a00c07",
            ),
            ..Default::default()
        };
        match delete_doc(&doc, FailingDelete {}).await {
            Ok(_) => panic!("expected error"),
            Err(e) => assert!(e.to_string().contains("Delete failed")),
        };

        Ok(())
    }
}
