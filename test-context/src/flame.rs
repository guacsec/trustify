use tracing_flame::FlameLayer;
use tracing_subscriber::{EnvFilter, fmt, prelude::*, registry::Registry};

/// set up a global tracing subscriber, generating a trace file for flamecharts.
///
/// ## Usage
///
/// Add this to a test, using the following pattern:
///
/// ```rust
/// use trustify_test_context::flame::setup_global_subscriber;
///
/// #[test]
/// fn test() {
///   let _guard = setup_global_subscriber();
///
///   // test code
/// }
/// ```
///
/// If the test ran successfully, this will create a file named `tracing.folded` containing the
/// result.
///
#[allow(clippy::test_attr_in_doctest)]
#[allow(clippy::unwrap_used)]
pub fn setup_global_subscriber() -> impl Drop {
    // Bridge log crate to tracing
    let _ = tracing_log::LogTracer::init();

    // Use EnvFilter to respect RUST_LOG environment variable
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = fmt::Layer::default();

    let (flame_layer, _guard) = FlameLayer::with_file("./tracing.folded").unwrap();

    let subscriber = Registry::default()
        .with(env_filter)
        .with(fmt_layer)
        .with(flame_layer);

    tracing::subscriber::set_global_default(subscriber).expect("Could not set global default");
    _guard
}
