//! Run correlation from one advisory JSON file and one SBOM JSON file.

use std::{env, fs};

use anyhow::{Context, Result};
use trustify_module_correlation::{
    collector::VecCollector, engine::correlate, evidence::Evidence, extract, memory::AdvisoryIndex,
};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let advisory_path = args.next().context("missing advisory JSON path")?;
    let sbom_path = args.next().context("missing SBOM JSON path")?;

    let advisory_json = read_json(&advisory_path)?;
    let sbom_json = read_json(&sbom_path)?;

    let advisory = extract::extract_advisory(&advisory_path, &advisory_json)
        .ok_or_else(|| anyhow::anyhow!("unrecognized advisory format: {advisory_path}"))?;
    let sbom = extract::extract_sbom(&sbom_path, &sbom_json)
        .ok_or_else(|| anyhow::anyhow!("unrecognized SBOM format: {sbom_path}"))?;

    let mut advisories = AdvisoryIndex::new();
    advisories.add(advisory);

    let evidence = Evidence::new(advisories.evidence(), sbom);
    let mut collector = VecCollector::default();
    let verdicts = correlate(&evidence, &mut collector);

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
