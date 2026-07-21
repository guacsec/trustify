use crate::analyze::ScanResult;
use crate::error::Error;

/// Render scan results in a compact grype-style list format.
pub fn render(result: &ScanResult, verbose: u8) -> Result<(), Error> {
    // Print summary banner.
    print_summary(result);

    // Print verbose PURL listing if requested.
    super::print_verbose_details(result, verbose);

    if result.vulnerabilities.is_empty() {
        return Ok(());
    }

    // Print column header.
    println!(
        "{:<30} {:<20} {:<14} {:<21} {:<10} {:<8}",
        "NAME", "INSTALLED", "TYPE", "VULNERABILITY", "SEVERITY", "STATUS"
    );

    for vuln in &result.vulnerabilities {
        let severity = vuln.severity.as_deref().unwrap_or("");
        let severity_colored = colorize_severity(severity);

        // Truncate long names to keep columns aligned.
        let name = truncate(&vuln.package_name, 29);
        let version = truncate(&vuln.package_version, 19);
        let pkg_type = truncate(&vuln.package_type, 13);
        let vuln_id = truncate(&vuln.vulnerability_id, 20);
        let status = truncate(&vuln.status, 7);

        println!(
            "{name:<30} {version:<20} {pkg_type:<14} {vuln_id:<21} {severity_colored:<19} {status}",
        );
    }

    Ok(())
}

/// Print the grype-style summary banner with severity breakdown.
fn print_summary(result: &ScanResult) {
    let total = result.vulnerabilities.len();
    let critical = count_severity(&result.vulnerabilities, "critical");
    let high = count_severity(&result.vulnerabilities, "high");
    let medium = count_severity(&result.vulnerabilities, "medium");
    let low = count_severity(&result.vulnerabilities, "low");
    let unknown = total - critical - high - medium - low;

    if result.total_packages == 0 {
        println!(
            " \x1b[33m\u{26a0}\x1b[0m No packages discovered          \
             [nothing to analyze]"
        );
        if result.ecosystems_searched.is_empty() {
            println!("   \u{251c}\u{2500}\u{2500} no recognized dependency files found");
            println!(
                "   \u{2514}\u{2500}\u{2500} supported files: {}",
                crate::cataloger::supported_file_patterns().join(", ")
            );
        } else {
            println!(
                "   \u{2514}\u{2500}\u{2500} searched ecosystems: {}",
                result.ecosystems_searched.join(", ")
            );
        }
        return;
    }

    if total == 0 {
        println!(
            " \x1b[32m\u{2714}\x1b[0m Scanned for vulnerabilities     \
             [0 vulnerability matches]"
        );
        print!(
            "   \u{2514}\u{2500}\u{2500} {} packages scanned, {} analyzed",
            result.total_packages, result.analyzed_packages
        );
        if !result.ecosystems_searched.is_empty() {
            print!(" ({})", result.ecosystems_searched.join(", "));
        }
        println!();
        return;
    }

    println!(
        " \x1b[32m\u{2714}\x1b[0m Scanned for vulnerabilities     \
         [{total} vulnerability matches]"
    );
    print!("   \u{251c}\u{2500}\u{2500} by severity: ");
    let mut parts = Vec::new();
    if critical > 0 {
        parts.push(format!("\x1b[31m{critical} critical\x1b[0m"));
    }
    if high > 0 {
        parts.push(format!("\x1b[31m{high} high\x1b[0m"));
    }
    if medium > 0 {
        parts.push(format!("\x1b[33m{medium} medium\x1b[0m"));
    }
    if low > 0 {
        parts.push(format!("\x1b[36m{low} low\x1b[0m"));
    }
    if unknown > 0 {
        parts.push(format!("{unknown} unknown"));
    }
    println!("{}", parts.join(", "));

    print!(
        "   \u{2514}\u{2500}\u{2500} {} packages scanned, {} analyzed",
        result.total_packages, result.analyzed_packages
    );
    if !result.ecosystems_searched.is_empty() {
        print!(" ({})", result.ecosystems_searched.join(", "));
    }
    if !result.warnings.is_empty() {
        print!(" ({} warnings)", result.warnings.len());
    }
    println!();
}

/// Colorize a severity string with ANSI escape codes.
fn colorize_severity(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => "\x1b[31mCritical\x1b[0m".to_string(),
        "high" => "\x1b[31mHigh\x1b[0m".to_string(),
        "medium" => "\x1b[33mMedium\x1b[0m".to_string(),
        "low" => "\x1b[36mLow\x1b[0m".to_string(),
        "" => String::new(),
        other => other.to_string(),
    }
}

/// Count vulnerabilities matching a severity (case-insensitive).
fn count_severity(vulns: &[crate::analyze::VulnerabilityMatch], severity: &str) -> usize {
    vulns
        .iter()
        .filter(|v| {
            v.severity
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(severity))
        })
        .count()
}

/// Truncate a string to `max` characters, appending `…` if truncated.
///
/// Operates on char boundaries to avoid panics on multi-byte UTF-8.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 1).collect();
        format!("{truncated}…")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world", 8), "hello w…");
    }

    #[test]
    fn truncate_multibyte_utf8() {
        // 4 chars, each 3 bytes in UTF-8: should not panic.
        let s = "\u{00e9}\u{00e9}\u{00e9}\u{00e9}";
        let result = truncate(s, 3);
        assert_eq!(result.chars().count(), 3); // 2 chars + '…'
    }
}
