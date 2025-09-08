use core::fmt;
use opentelemetry::{
    Context,
    global::{
        get_text_map_propagator, set_meter_provider, set_text_map_propagator, set_tracer_provider,
    },
    propagation::Injector,
    trace::TracerProvider as _,
};
use opentelemetry_otlp::{MetricExporter, SpanExporter};
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
    propagation::TraceContextPropagator,
    trace::{Sampler, Sampler::ParentBased, SdkTracerProvider},
};
use reqwest::RequestBuilder;
use std::sync::Once;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{
    EnvFilter, field::MakeExt, layer::SubscriberExt, util::SubscriberInitExt,
};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Default)]
pub enum Metrics {
    #[clap(name = "disabled")]
    #[default]
    Disabled,
    #[clap(name = "enabled")]
    Enabled,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Default)]
pub enum Tracing {
    #[clap(name = "disabled")]
    #[default]
    Disabled,
    #[clap(name = "enabled")]
    Enabled,
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Metrics::Disabled => write!(f, "disabled"),
            Metrics::Enabled => write!(f, "enabled"),
        }
    }
}

impl fmt::Display for Tracing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tracing::Disabled => write!(f, "disabled"),
            Tracing::Enabled => write!(f, "enabled"),
        }
    }
}

pub trait PropagateCurrentContext {
    fn propagate_current_context(self) -> Self
    where
        Self: Sized;
}

impl PropagateCurrentContext for RequestBuilder {
    #[inline]
    fn propagate_current_context(self) -> Self
    where
        Self: Sized,
    {
        self.propagate_context(&Context::current())
    }
}

pub trait WithTracing {
    fn propagate_context(self, cx: &Context) -> Self;
}

impl WithTracing for RequestBuilder {
    fn propagate_context(self, cx: &Context) -> Self {
        let headers = get_text_map_propagator(|prop| {
            let mut injector = HeaderInjector::new();
            prop.inject_context(cx, &mut injector);
            injector.0
        });
        self.headers(headers)
    }
}

struct HeaderInjector(http::HeaderMap);

impl HeaderInjector {
    pub fn new() -> Self {
        Self(Default::default())
    }
}

impl Injector for HeaderInjector {
    /// Set a key and value in the HeaderMap.  Does nothing if the key or value are not valid inputs.
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes())
            && let Ok(val) = http::header::HeaderValue::from_str(&value)
        {
            self.0.insert(name, val);
        }
    }
}

/// Try getting the sampling rate from the environment variables
fn sampling_from_env() -> Option<f64> {
    std::env::var_os("OTEL_TRACES_SAMPLER_ARG")
        .and_then(|s| s.to_str().and_then(|s| s.parse::<f64>().ok()))
}

fn sampler() -> Sampler {
    if let Some(p) = sampling_from_env() {
        Sampler::TraceIdRatioBased(p)
    } else {
        Sampler::TraceIdRatioBased(0.001)
    }
}

static INIT: Once = Once::new();
pub fn init_tracing(name: &str, tracing: Tracing) {
    match tracing {
        Tracing::Disabled => {
            INIT.call_once(init_no_tracing);
        }
        Tracing::Enabled => {
            init_otlp_tracing(name);
        }
    }
}

pub fn init_metrics(name: &'static str, metrics: Metrics) {
    if let Metrics::Enabled = metrics {
        init_otlp_metrics(name);
    }
}

fn init_otlp_metrics(name: &str) {
    #[allow(clippy::expect_used)]
    let exporter = MetricExporter::builder()
        .with_tonic()
        .build()
        .expect("Unable to build metrics exporter.");

    let reader = PeriodicReader::builder(exporter).build();

    let resource = Resource::builder()
        .with_service_name(name.to_string())
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    println!("Exporting metrics to OTEL Collector.");
    println!("{provider:#?}");

    set_meter_provider(provider);
}

fn init_otlp_tracing(name: &str) {
    set_text_map_propagator(TraceContextPropagator::new());

    #[allow(clippy::expect_used)]
    let exporter = SpanExporter::builder()
        .with_tonic()
        .build()
        .expect("Unable to build tracing exporter");

    let resource = Resource::builder()
        .with_service_name(name.to_string())
        .build();

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .with_sampler(ParentBased(Box::new(sampler())))
        .build();

    println!("Exporting traces to OTEL Collector.");
    println!("{provider:#?}");

    let formatting_layer = tracing_subscriber::fmt::Layer::default();
    let tracer = provider.tracer(name.to_string());

    if let Err(e) = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(OpenTelemetryLayer::new(tracer))
        .with(formatting_layer)
        .try_init()
    {
        eprintln!("Error initializing tracing: {e:?}");
    }
    set_tracer_provider(provider);
}

fn init_no_tracing() {
    const RUST_LOG: &str = "info";

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        eprintln!("RUST_LOG is unset, using default: '{RUST_LOG}'");
        EnvFilter::new(RUST_LOG)
    });

    let result = tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .map_fmt_fields(|f| f.debug_alt())
                .with_level(true)
                .with_thread_ids(true)
                .compact(),
        )
        .try_init();

    if let Err(err) = result {
        eprintln!("Error initializing logging: {err:?}");
    }
}
