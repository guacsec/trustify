//! Settings of the correlation worker.

use crate::error::Error;
use bytesize::ByteSize;
use sea_orm::{ConnectionTrait, DatabaseTransaction};
use std::num::NonZeroUsize;
use trustify_common::db::sql;

/// The smallest `work_mem` PostgreSQL accepts.
const MIN_WORK_MEM: ByteSize = ByteSize::kib(64);
/// The largest `work_mem` PostgreSQL accepts (`INT_MAX` kB).
const MAX_WORK_MEM: ByteSize = ByteSize::kib(i32::MAX as u64);
/// The default of [`WorkerConfig::match_batch`].
pub const DEFAULT_MATCH_BATCH: usize = 100_000;

/// Settings of the correlation worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerConfig {
    /// The number of workers of an instance, see
    /// [`run_extraction_workers`](crate::extractor::worker::run_extraction_workers).
    pub workers: NonZeroUsize,
    /// The `work_mem` of the worker's transactions, `None` keeps the database's setting.
    ///
    /// Matching packages with many statements (e.g. the kernel of a RHEL SBOM) aggregates
    /// millions of rows, which spill to disk with PostgreSQL's default of 4 MB.
    pub work_mem: Option<ByteSize>,
    /// The number of matches of an SBOM held in memory before their evidence is written.
    ///
    /// The matches of a node are written together, so a node with more matches (e.g. the kernel of
    /// a RHEL SBOM) exceeds it.
    pub match_batch: usize,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            workers: NonZeroUsize::MIN,
            work_mem: None,
            match_batch: DEFAULT_MATCH_BATCH,
        }
    }
}

impl WorkerConfig {
    /// Apply the settings to a transaction, for its duration only (`SET LOCAL`).
    pub async fn apply(&self, tx: &DatabaseTransaction) -> Result<(), Error> {
        if let Some(work_mem) = self.work_mem {
            tx.execute_raw(sql(
                "SELECT set_config('work_mem', $1, true)",
                vec![format!("{}kB", work_mem.as_u64() / 1024).into()],
            ))
            .await?;
        }
        Ok(())
    }
}

/// Parse a `work_mem` value, within the range PostgreSQL accepts.
pub fn parse_work_mem(value: &str) -> Result<ByteSize, String> {
    let size = value.parse::<ByteSize>()?;
    if (MIN_WORK_MEM..=MAX_WORK_MEM).contains(&size) {
        Ok(size)
    } else {
        Err(format!(
            "must be between {} and {}",
            MIN_WORK_MEM.display().iec(),
            MAX_WORK_MEM.display().iec()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test]
    fn parse() {
        assert_eq!(parse_work_mem("256MiB"), Ok(ByteSize::mib(256)));
        assert_eq!(parse_work_mem("64KiB"), Ok(ByteSize::kib(64)));
        assert_eq!(
            parse_work_mem("1KiB"),
            Err("must be between 64.0 KiB and 2.0 TiB".to_string())
        );
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn applies_to_the_transaction_only(ctx: &TrustifyContext) -> anyhow::Result<()> {
        use sea_orm::TransactionTrait;

        let show = async |tx: &DatabaseTransaction| -> anyhow::Result<String> {
            let row = tx
                .query_one_raw(sql("SHOW work_mem", vec![]))
                .await?
                .ok_or_else(|| anyhow::anyhow!("no work_mem"))?;
            Ok(row.try_get("", "work_mem")?)
        };

        let tx = ctx.db.begin().await?;
        let default = show(&tx).await?;
        WorkerConfig::default().apply(&tx).await?;
        assert_eq!(show(&tx).await?, default);
        WorkerConfig {
            work_mem: Some(ByteSize::mib(256)),
            ..Default::default()
        }
        .apply(&tx)
        .await?;
        assert_eq!(show(&tx).await?, "256MB");
        tx.commit().await?;

        let tx = ctx.db.begin().await?;
        assert_eq!(show(&tx).await?, default);
        Ok(())
    }
}
