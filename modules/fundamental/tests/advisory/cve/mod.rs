#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod delete;
mod parallel;
mod reingest;

use cve::{
    Cve, Rejected,
    common::{self, Description},
    rejected::{CnaContainer, Containers, Metadata, State},
};
use time::macros::datetime;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::{TrustifyContext, document_bytes};

/// Ingest a document twice, mutating it using the provided closure.
async fn twice<M1, M2>(
    ctx: &TrustifyContext,
    m1: M1,
    m2: M2,
) -> anyhow::Result<(IngestResult, IngestResult)>
where
    M1: FnOnce(Cve) -> Cve,
    M2: FnOnce(Cve) -> Cve,
{
    let data = document_bytes("cve/CVE-2021-32714.json").await?;
    let cve: Cve = serde_json::from_slice(&data)?;

    let cve = m1(cve);

    let result = ctx
        .ingest_read(serde_json::to_vec(&cve)?.as_slice())
        .await?;

    let cve = m2(cve);

    let result2 = ctx
        .ingest_read(serde_json::to_vec(&cve)?.as_slice())
        .await?;

    Ok((result, result2))
}

/// Update a CVE, marking it as rejected with a timestamp of 2024-01-01 00:00 UTC.
fn update_mark_rejected(cve: Cve) -> Cve {
    let updated = datetime!(2024-01-01 00:00:00 UTC);
    match cve {
        Cve::Published(cve) => Cve::Rejected(Rejected {
            data_type: cve.data_type,
            data_version: cve.data_version,
            metadata: Metadata {
                state: State,
                common: common::Metadata {
                    date_updated: Some(updated.into()),
                    ..cve.metadata.common
                },
                date_rejected: Some(updated.into()),
            },
            containers: Containers {
                cna: CnaContainer {
                    common: cve.containers.cna.common,
                    rejected_reasons: vec![Description {
                        language: "en".to_string(),
                        value: "Just a test".to_string(),
                        supporting_media: vec![],
                    }],
                    replaced_by: vec![],
                },
            },
        }),
        _ => {
            panic!("must be published");
        }
    }
}
