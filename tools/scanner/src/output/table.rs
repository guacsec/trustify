use crate::analyze::ScanResult;
use crate::error::Error;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};

/// Render scan results as a human-readable table.
pub fn render(result: &ScanResult, verbose: u8) -> Result<(), Error> {
    // Print verbose PURL listing if requested.
    super::print_verbose_details(result, verbose);

    if result.vulnerabilities.is_empty() {
        println!("No vulnerabilities found.");
        return Ok(());
    }

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("NAME").add_attribute(Attribute::Bold),
        Cell::new("INSTALLED").add_attribute(Attribute::Bold),
        Cell::new("TYPE").add_attribute(Attribute::Bold),
        Cell::new("VULNERABILITY").add_attribute(Attribute::Bold),
        Cell::new("SEVERITY").add_attribute(Attribute::Bold),
        Cell::new("SCORE").add_attribute(Attribute::Bold),
        Cell::new("STATUS").add_attribute(Attribute::Bold),
        Cell::new("ADVISORY").add_attribute(Attribute::Bold),
    ]);

    for vuln in &result.vulnerabilities {
        let severity_cell = match vuln.severity.as_deref() {
            Some("critical") | Some("Critical") => Cell::new("Critical").fg(Color::Red),
            Some("high") | Some("High") => Cell::new("High").fg(Color::Red),
            Some("medium") | Some("Medium") => Cell::new("Medium").fg(Color::Yellow),
            Some("low") | Some("Low") => Cell::new("Low").fg(Color::Cyan),
            Some(s) => Cell::new(s),
            None => Cell::new(""),
        };

        let score_str = vuln.score.map(|s| format!("{s:.1}")).unwrap_or_default();

        table.add_row(vec![
            Cell::new(&vuln.package_name),
            Cell::new(&vuln.package_version),
            Cell::new(&vuln.package_type),
            Cell::new(&vuln.vulnerability_id),
            severity_cell,
            Cell::new(&score_str),
            Cell::new(&vuln.status),
            Cell::new(&vuln.advisory),
        ]);
    }

    println!("{table}");

    // Summary line.
    let total = result.vulnerabilities.len();
    let critical = result
        .vulnerabilities
        .iter()
        .filter(|v| matches!(v.severity.as_deref(), Some("critical" | "Critical")))
        .count();
    let high = result
        .vulnerabilities
        .iter()
        .filter(|v| matches!(v.severity.as_deref(), Some("high" | "High")))
        .count();

    println!("\n{total} vulnerabilities found ({critical} critical, {high} high)");

    Ok(())
}
