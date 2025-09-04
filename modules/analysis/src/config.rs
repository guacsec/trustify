use bytesize::ByteSize;
use std::num::NonZeroUsize;
use trustify_common::model::BinaryByteSize;

fn parse_concurrency(s: &str) -> Result<NonZeroUsize, String> {
    let value: usize = s.parse().map_err(|e| format!("Invalid number: {e}"))?;
    NonZeroUsize::new(value).ok_or_else(|| "Concurrency must be greater than zero".to_string())
}

const DEFAULT_CONCURRENCY: NonZeroUsize = match NonZeroUsize::new(10) {
    Some(val) => val,
    None => panic!("Default concurrency must be non-zero integer"),
};

#[derive(clap::Args, Debug, Clone)]
pub struct AnalysisConfig {
    #[arg(
        id = "max-cache-size",
        long,
        env = "TRUSTD_MAX_CACHE_SIZE",
        default_value = "200 MiB",
        help = "Maximum size of the graph cache."
    )]
    pub max_cache_size: BinaryByteSize,

    #[arg(
        long,
        env = "TRUSTIFY_ANALYSIS_CONCURRENCY",
        default_value = "10",
        value_parser = parse_concurrency,
        help = "The number of concurrent tasks for analysis (must be > 0)."
    )]
    pub concurrency: NonZeroUsize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_cache_size: BinaryByteSize(ByteSize::mib(200)),
            concurrency: DEFAULT_CONCURRENCY,
        }
    }
}
