#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

mod delete;
mod ingest;
mod parallel;
mod reingest;

use osv::schema::{Event, Vulnerability};
use trustify_module_ingestor::model::IngestResult;
use trustify_module_ingestor::service::advisory::osv::{from_yaml, to_yaml};
use trustify_test_context::{TrustifyContext, document_bytes};

/// Ingest a document twice, mutating it using the provided closure.
async fn twice<M1, M2>(
    ctx: &TrustifyContext,
    m1: M1,
    m2: M2,
) -> anyhow::Result<(IngestResult, IngestResult)>
where
    M1: FnOnce(Vulnerability) -> Vulnerability,
    M2: FnOnce(Vulnerability) -> Vulnerability,
{
    let data = document_bytes("osv/RSEC-2023-6.yaml").await?;
    let osv = from_yaml(&data)?;

    let osv = m1(osv);

    let result = ctx.ingest_read(to_yaml(&osv)?.as_bytes()).await?;

    let osv = m2(osv);

    let result2 = ctx.ingest_read(to_yaml(&osv)?.as_bytes()).await?;

    Ok((result, result2))
}

/// Update an OSV, removing the "fixed" state, so that we can, later on, add it again.
fn update_unmark_fixed(mut osv: Vulnerability) -> Vulnerability {
    // remove the "fixed" event
    osv.affected
        .as_mut()
        .expect("test data must have 'affected'")[0]
        .ranges
        .as_mut()
        .expect("must be expected test data")[0]
        .events
        .remove(1);

    osv
}

/// Add back the "fixed" event
fn update_mark_fixed_again(mut osv: Vulnerability) -> Vulnerability {
    osv.affected
        .as_mut()
        .expect("test data must have 'affected'")[0]
        .ranges
        .as_mut()
        .expect("must be expected test data")[0]
        .events
        .push(Event::Fixed("1.8".into()));

    osv
}
