use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

mod common;

#[allow(clippy::expect_used, clippy::unwrap_used)]
pub(crate) mod trustify_benches {
    use std::hint::black_box;
    use std::ops::Add;
    use std::time::{Duration, Instant};

    use crate::common;
    use criterion::Criterion;
    use trustify_entity::labels::Labels;
    use trustify_module_ingestor::service::{Cache, Format};

    pub fn ingestion(c: &mut Criterion) {
        let (runtime, ctx) = common::setup_runtime_and_ctx();
        c.bench_function("ingestion_csaf", |b| {
            b.to_async(&runtime).iter_custom(|count| {
                let ctx = ctx.clone();
                async move {
                    log::info!("db reset...");
                    common::reset_db(&ctx).await;

                    let mut duration = Duration::default();
                    for i in 0..count {
                        log::info!("inserting document {i}...");
                        let data = common::document_generated_from("csaf/cve-2023-33201.json", i)
                            .await
                            .expect("data ok");

                        let start = Instant::now();
                        black_box(
                            ctx.db
                                .transaction(async |tx| {
                                    ctx.ingestor
                                        .ingest(
                                            &data,
                                            Format::Advisory,
                                            Labels::default(),
                                            None,
                                            Cache::Skip,
                                            tx,
                                        )
                                        .await
                                })
                                .await
                                .expect("ingest ok"),
                        );
                        duration = duration.add(start.elapsed());
                    }

                    duration
                }
            });
        });
    }
}

criterion_group! {
  name = benches;
  // since insertion takes so long, we need to reduce the sample
  // size and increase the time so that we can get a few iterations
  // in between db resets.
  config = Criterion::default()
    .measurement_time(Duration::from_secs(15))
    .sample_size(10);
  targets = trustify_benches::ingestion
}
criterion_main!(benches);
