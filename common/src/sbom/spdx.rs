use sbom_walker::report::ReportSink;
use serde_json::Value;
use spdx_rs::models::SPDX;

/// Parse a SPDX document, possibly replacing invalid license expressions.
///
/// Returns the parsed document and a flag indicating if license expressions got replaced.
pub fn parse_spdx(report: &dyn ReportSink, json: Value) -> Result<(SPDX, bool), serde_json::Error> {
    let (json, changed) = fix_license(report, json);
    Ok((serde_json::from_value(json)?, changed))
}

/// Check the document for invalid SPDX license expressions and replace them with `NOASSERTION`.
pub fn fix_license(report: &dyn ReportSink, mut json: Value) -> (Value, bool) {
    let mut changed = false;
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            if let Some(declared) = package["licenseDeclared"].as_str()
                && let Err(err) = spdx_expression::SpdxExpression::parse(declared)
            {
                package["licenseDeclared"] = "NOASSERTION".into();
                changed = true;

                let message =
                    format!("Replacing faulty SPDX license expression with NOASSERTION: {err}");
                log::debug!("{message}");
                report.error(message);
            }
        }
    }

    (json, changed)
}
