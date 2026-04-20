use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use serde_json::Value;

use crate::Context;
use crate::api::advisory as advisory_api;
use crate::common::{ListParams, PruneParams};
use chrono::{DateTime, Local};

#[derive(Clone, Default, ValueEnum)]
pub enum ListFormat {
    #[default]
    Full,
}

#[derive(Clone, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Json,
}

#[derive(Subcommand)]
pub enum AdvisoryCommands {
    /// List advisories
    List {
        /// Query filter for advisories
        #[arg(long)]
        query: Option<String>,
        /// Limit the number of results
        #[arg(long)]
        limit: Option<u32>,
        /// Offset the results
        #[arg(long)]
        offset: Option<u32>,
        /// Sort the results
        #[arg(long)]
        sort: Option<String>,
    },
    /// Prune advisories
    Prune {
        /// Query filter for advisories to delete
        #[arg(long)]
        query: Option<String>,

        /// Perform a dry run without actually deleting
        #[arg(long)]
        dry_run: bool,

        /// Number of concurrent delete requests (default: 10)
        #[arg(long, default_value = "10")]
        concurrency: usize,

        /// Limit the number of advisories to query and delete (default: 100)
        #[arg(long, default_value = "100")]
        limit: Option<u32>,

        /// Prune advisories published before a certain date (format: RFC 3339, e.g., 2024-01-15T10:30:45Z)
        #[arg(long)]
        published_before: Option<String>,

        /// Prune advisories ingested before the given number of days
        #[arg(long)]
        older_than: Option<i64>,

        /// Label to filter advisories to delete (can be specified multiple times)
        #[arg(long)]
        label: Vec<String>,

        /// Keep N most recent advisories per identifier
        #[arg(long)]
        keep_latest: Option<u32>,

        /// Output file type (default: json)
        #[arg(long, default_value = "json")]
        output_type: Option<OutputFormat>,

        /// Output file path (default: advisories.json)
        #[arg(long, default_value = "advisories.json")]
        output: Option<String>,

        /// Quiet mode
        #[arg(long)]
        quiet: bool,
    },
}

fn format_list_output(json: &str, _format: &ListFormat) -> anyhow::Result<()> {
    let value: Value = serde_json::from_str(json)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

impl AdvisoryCommands {
    pub async fn run(&self, ctx: &Context) -> anyhow::Result<ExitCode> {
        match self {
            AdvisoryCommands::List {
                query,
                limit,
                offset,
                sort,
            } => {
                let params = ListParams {
                    q: query.clone(),
                    limit: *limit,
                    offset: *offset,
                    sort: sort.clone(),
                };
                let json = advisory_api::list(&ctx.client, &params).await?;
                format_list_output(&json, &ListFormat::Full)?;
                Ok(ExitCode::SUCCESS)
            }
            AdvisoryCommands::Prune {
                query,
                dry_run,
                concurrency,
                limit,
                published_before,
                older_than,
                label,
                keep_latest,
                output_type,
                output,
                quiet,
            } => {
                let published_before = if let Some(date_str) = published_before {
                    Some(DateTime::parse_from_rfc3339(date_str)
                        .map_err(|e| anyhow::anyhow!("Invalid date format for published_before: {}. Expected RFC 3339 format (e.g., 2024-01-15T10:30:45Z)", e))?
                        .with_timezone(&Local))
                } else {
                    None
                };

                let params = PruneParams {
                    q: query.clone(),
                    limit: *limit,
                    published_before,
                    older_than: *older_than,
                    label: Some(label.clone()).filter(|l| !l.is_empty()),
                    keep_latest: *keep_latest,
                    dry_run: *dry_run,
                    concurrency: *concurrency,
                };

                let prune_result = advisory_api::prune(&ctx.client, &params).await?;

                if !quiet {
                    if *dry_run {
                        println!(
                            "[DRY-RUN] Would delete {} advisory(s)",
                            prune_result.deleted_total
                        );
                    } else {
                        let mut msg = format!("Deleted {} advisory(s)", prune_result.deleted_total);
                        if prune_result.skipped_total > 0 {
                            msg.push_str(&format!(
                                ", {} skipped (not found)",
                                prune_result.skipped_total
                            ));
                        }
                        if prune_result.failed_total > 0 {
                            msg.push_str(&format!(", {} failed", prune_result.failed_total));
                        }
                        msg.push_str(&format!(" out of {} total", prune_result.total));
                        println!("{}", msg);
                    }
                }

                if let Some(output_path) = output {
                    match output_type.as_ref() {
                        Some(OutputFormat::Json) | None => {
                            let json =
                                serde_json::to_string_pretty(&prune_result).map_err(|e| {
                                    anyhow::anyhow!("Failed to serialize result: {}", e)
                                })?;
                            std::fs::write(output_path, json)
                                .map_err(|e| anyhow::anyhow!("Failed to write to file: {}", e))?;
                        }
                    }
                }

                Ok(ExitCode::SUCCESS)
            }
        }
    }
}
