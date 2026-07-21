use crate::analyze::ScanResult;
use crate::error::Error;

/// Render scan results as structured JSON to stdout.
pub fn render(result: &ScanResult) -> Result<(), Error> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{json}");
    Ok(())
}
