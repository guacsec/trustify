use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

mod common;

#[allow(clippy::expect_used, clippy::unwrap_used)]
pub(crate) mod trustify_benches {
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    use criterion::Criterion;
    use std::ops::Add;
    use trustify_entity::labels::Labels;
    use trustify_module_ingestor::service::{Cache, Format};

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::{
        Resource,
        trace::{Sampler, SdkTracerProvider},
    };
    use tracing_core::Level;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    use crate::common;

    fn resource() -> Resource {
        Resource::builder()
            .with_service_name("ingestion_csaf".to_string())
            .build()
    }

    fn init_tracer_provider() -> SdkTracerProvider {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()
            .unwrap();

        SdkTracerProvider::builder()
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                1.0,
            ))))
            .with_resource(resource())
            .with_batch_exporter(exporter)
            .build()
    }

    pub fn init_tracing_subscriber() {
        let tracer_provider = init_tracer_provider();

        let tracer = tracer_provider.tracer("tracing-opentelemetry");

        tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::from_level(
                Level::INFO,
            ))
            .with(tracing_subscriber::fmt::layer())
            .with(OpenTelemetryLayer::new(tracer))
            .init();
    }

    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn ingestion(c: &mut Criterion) {
        let (runtime, ctx) = common::setup_runtime_and_ctx();
        c.bench_function("ingestion_csaf", |b| {
            b.to_async(&runtime).iter_custom(|count| {
                let ctx = ctx.clone();
                async move {
                    INIT.call_once(init_tracing_subscriber);
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
                            ctx.ingestor
                                .ingest(
                                    &data,
                                    Format::Advisory,
                                    Labels::default(),
                                    None,
                                    Cache::Skip,
                                )
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
