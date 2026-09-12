//! Run correlation from one advisory JSON file and one SBOM JSON file.

use std::{env, fs};

use anyhow::{Context, Result, bail};
use trustify_module_correlation::{
    collector::VecCollector,
    engine::correlate_with_options,
    evidence::Evidence,
    extract,
    memory::AdvisoryIndex,
    options::{CorrelationOptions, VersionlessMatchPolicy},
};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let advisory_path = args.next().context("missing advisory JSON path")?;
    let sbom_path = args.next().context("missing SBOM JSON path")?;
    let allow_versionless = match args.next().as_deref() {
        None => false,
        Some("--allow-versionless") => true,
        Some(value) => bail!("unknown option: {value}"),
    };

    let advisory_json = read_json(&advisory_path)?;
    let sbom_json = read_json(&sbom_path)?;

    let advisory = extract::extract_advisory(&advisory_path, &advisory_json)
        .ok_or_else(|| anyhow::anyhow!("unrecognized advisory format: {advisory_path}"))?;
    let sbom = extract::extract_sbom(&sbom_path, &sbom_json)
        .ok_or_else(|| anyhow::anyhow!("unrecognized SBOM format: {sbom_path}"))?;

    let mut advisories = AdvisoryIndex::new();
    advisories.add(advisory);

    let evidence = Evidence::new(advisories.evidence(), sbom);
    let options = CorrelationOptions {
        versionless_matches: if allow_versionless {
            VersionlessMatchPolicy::Allow
        } else {
            VersionlessMatchPolicy::Reject
        },
        ..CorrelationOptions::default()
    };
    let mut collector = VecCollector::default();
    let verdicts = correlate_with_options(&evidence, &options, &mut collector);

    for verdict in verdicts {
        println!(
            "{}: {} ({:?})",
            verdict.vulnerability_id,
            verdict.status.as_str(),
            verdict.resolution_rule
        );
    }

    Ok(())
}

fn read_json(path: &str) -> Result<serde_json::Value> {
    let content = fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    serde_json::from_str(&content).with_context(|| format!("parsing {path}"))
}
