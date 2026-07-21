pub mod json;
pub mod list;
pub mod table;

use crate::analyze::ScanResult;
use crate::error::Error;

/// Supported output formats.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// Compact grype-style list with severity summary (default).
    #[default]
    List,
    /// Bordered table with detailed columns.
    Table,
    /// Structured JSON.
    Json,
}

/// Format and print scan results.
pub fn render(result: &ScanResult, format: OutputFormat, verbose: u8) -> Result<(), Error> {
    match format {
        OutputFormat::List => list::render(result, verbose),
        OutputFormat::Table => table::render(result, verbose),
        OutputFormat::Json => json::render(result),
    }
}

/// Print verbose details: discovered PURLs grouped by type.
pub fn print_verbose_details(result: &ScanResult, verbose: u8) {
    if verbose == 0 || result.purls.is_empty() {
        return;
    }

    // Group PURLs by type for a cleaner display.
    let mut by_type: std::collections::BTreeMap<&str, Vec<&str>> =
        std::collections::BTreeMap::new();
    for purl in &result.purls {
        let pkg_type = purl
            .strip_prefix("pkg:")
            .and_then(|s| s.split('/').next())
            .unwrap_or("unknown");
        by_type.entry(pkg_type).or_default().push(purl);
    }

    println!();
    println!("Discovered packages ({} total):", result.purls.len());
    for (pkg_type, purls) in &by_type {
        println!("  {pkg_type} ({}):", purls.len());
        for purl in purls {
            println!("    {purl}");
        }
    }
}
