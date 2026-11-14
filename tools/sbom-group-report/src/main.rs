//! Renders an HTML vulnerability report for every SBOM in a Trustify SBOM
//! group, including the SBOMs of its nested child groups.

mod auth;
mod groups;
mod report;

use std::{collections::HashSet, num::NonZeroU64, path::PathBuf};

use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};
use futures::{StreamExt, TryStreamExt, stream};
use trustify_client::{
    OffsetPage, TrustifyClient,
    api::{ClientSbomExt, ClientSbomGroupExt},
    collect_offset_pages,
};

use crate::{
    auth::ClientCredentials,
    groups::GroupNode,
    report::{Report, SbomRow},
};

#[derive(Parser)]
#[command(about = "Batch vulnerability report for a Trustify SBOM group and its nested groups")]
struct Args {
    /// ID or name of the SBOM group to report on.
    group: String,

    /// Base URL of the Trustify server.
    #[arg(long, env = "TRUSTIFY_URL", default_value = "http://localhost:8080")]
    url: String,

    /// OIDC issuer to obtain a token from, with --client-id and CLIENT_SECRET.
    #[arg(long, env = "ISSUER_URL")]
    issuer_url: Option<String>,

    /// OIDC client ID for the client_credentials grant.
    #[arg(long, env = "CLIENT_ID")]
    client_id: Option<String>,

    /// Send credentials to a non-loopback host over plain HTTP anyway.
    #[arg(long)]
    insecure: bool,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Report format: a full HTML document, or the detail table as CSV.
    #[arg(long, short, value_enum, default_value_t = Format::Html)]
    format: Format,

    /// How deep below the group to follow nested child groups.
    #[arg(long, default_value_t = 16)]
    max_depth: usize,

    /// How many SBOMs to query for advisories at a time.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// Fail instead of reporting when the group holds more SBOMs than this.
    #[arg(long, default_value_t = 2000)]
    max_sboms: usize,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Html,
    Csv,
}

const PAGE_SIZE: u64 = 200;
const MAX_GROUPS: u64 = 10_000;

/// Read a credential from the environment, treating empty as unset.
fn secret(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.concurrency == 0 {
        bail!("--concurrency must be at least 1");
    }
    let Some(page_size) = NonZeroU64::new(PAGE_SIZE) else {
        bail!("PAGE_SIZE must not be zero");
    };
    // Lenient: Trustify is commonly reached over plain HTTP inside a cluster.
    // The OIDC URLs, which carry the client secret, are checked strictly.
    let instance_url = auth::parse_url(&args.url, "TRUSTIFY_URL", false)?;

    // Secrets come from the environment only: process arguments are readable by
    // every other user on the host.
    let token = secret("TRUSTIFY_TOKEN");
    let client_secret = secret("CLIENT_SECRET");

    if (token.is_some() || args.issuer_url.is_some())
        && instance_url.scheme() != "https"
        && !auth::is_loopback(&instance_url)
        && !args.insecure
    {
        bail!(
            "refusing to send credentials to {instance_url} over plain HTTP; pass --insecure to allow it"
        );
    }

    let mut client = TrustifyClient::builder(&args.url);
    match (&token, &args.issuer_url, &args.client_id, &client_secret) {
        (Some(token), ..) => {
            if token.to_ascii_lowercase().starts_with("bearer ") {
                bail!("the token must not include the 'Bearer ' prefix");
            }
            client = client.bearer_token(token.clone());
        }
        (None, Some(issuer), Some(id), Some(secret)) => {
            client = client.token_provider(
                ClientCredentials::discover(issuer, id.clone(), secret.clone())
                    .await
                    .context("setting up OIDC client-credentials authentication")?,
            );
        }
        (None, None, None, None) => {}
        _ => bail!(
            "OIDC needs all of --issuer-url, --client-id and CLIENT_SECRET; \
             set TRUSTIFY_TOKEN instead for a ready-made bearer token"
        ),
    }
    let client = client.build().context("building the Trustify client")?;

    let all_groups = collect_offset_pages(page_size, |offset, limit| {
        let client = &client;
        async move {
            let page = client
                .api()
                .list_sbom_groups()
                // Offset paging over an unordered list can skip or repeat rows.
                .sort("id")
                .offset(offset as i64)
                .limit(limit as i64)
                .total(true)
                .send()
                .await?
                .into_inner();
            if page.total.is_some_and(|total| total > MAX_GROUPS as i64)
                || offset.saturating_add(page.items.len() as u64) > MAX_GROUPS
            {
                bail!("group inventory exceeds the {MAX_GROUPS} group safety limit");
            }
            anyhow::Ok(OffsetPage::new(
                page.items,
                page.total.map(|total| total.max(0) as u64),
            ))
        }
    })
    .await
    .context("listing SBOM groups")?;

    let nodes: Vec<GroupNode> = all_groups
        .iter()
        .map(|group| GroupNode {
            id: group.id.clone(),
            name: group.name.clone(),
            parent: group.parent.clone(),
        })
        .collect();
    let root = groups::resolve(&args.group, &nodes)?;
    let group_ids = groups::subtree(&root.id, &nodes, args.max_depth)?;

    // One request per group: the `group` filter matches direct assignments
    // only, and an SBOM assigned to several groups in the subtree repeats.
    let mut seen = HashSet::new();
    let mut sboms = Vec::new();
    let limit = PAGE_SIZE.min(args.max_sboms.saturating_add(1) as u64) as i64;
    for group_id in &group_ids {
        let mut offset = 0;
        loop {
            let page = client
                .api()
                .list_sboms()
                .group(vec![group_id.clone()])
                .offset(offset as i64)
                .limit(limit)
                .total(true)
                .send()
                .await
                .with_context(|| format!("listing SBOMs of group {group_id}"))?
                .into_inner();
            let count = page.items.len();
            offset += count;
            if page
                .total
                .is_some_and(|total| total > args.max_sboms as i64)
                || offset > args.max_sboms
            {
                bail!("group inventory exceeds --max-sboms {}", args.max_sboms);
            }

            for sbom in page.items {
                if seen.insert(sbom.id.clone()) {
                    if sboms.len() == args.max_sboms {
                        bail!("group subtree exceeds --max-sboms {}", args.max_sboms);
                    }
                    sboms.push(sbom);
                }
            }
            if count == 0 || page.total.is_some_and(|total| offset as i64 >= total) {
                break;
            }
        }
    }

    let rows: Vec<SbomRow> = stream::iter(&sboms)
        .map(|sbom| {
            let client = &client;
            let instance_url = &instance_url;
            async move {
                let advisories = client
                    .api()
                    .get_sbom_advisories()
                    .id(sbom.id.clone())
                    .send()
                    .await
                    .with_context(|| format!("fetching advisories for SBOM {}", sbom.id))?
                    .into_inner();
                let mut url = instance_url.clone();
                url.path_segments_mut()
                    .map_err(|_| anyhow::anyhow!("Trustify URL cannot contain path segments"))?
                    .pop_if_empty()
                    .push("sboms")
                    .push(&sbom.id);
                url.query_pairs_mut()
                    .append_pair("sd:activeTab", "vulnerabilities");
                anyhow::Ok(SbomRow {
                    name: sbom.name.clone(),
                    url: url.to_string(),
                    packages: sbom.number_of_packages,
                    findings: report::findings(&advisories),
                })
            }
        })
        .buffer_unordered(args.concurrency)
        .try_collect()
        .await?;

    let report = Report {
        instance_url: instance_url.to_string(),
        group_name: root.name.clone(),
        group_id: root.id.clone(),
        groups_scanned: group_ids.len(),
        generated: chrono::Utc::now(),
        rows,
    };
    let rendered = match args.format {
        Format::Html => report::render_html(&report),
        Format::Csv => report::render_csv(&report),
    };

    match args.output {
        Some(path) => std::fs::write(&path, rendered)
            .with_context(|| format!("writing {}", path.display()))?,
        None => print!("{rendered}"),
    }

    Ok(())
}
