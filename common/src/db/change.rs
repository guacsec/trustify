use sea_orm::{ConnectionTrait, DbErr, Statement};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use uuid::Uuid;

const CHANNEL: &str = "trustify_changes";
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// The kind of entity that changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeEntity {
    Advisory,
    Sbom,
}

impl ChangeEntity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Sbom => "sbom",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "advisory" => Some(Self::Advisory),
            "sbom" => Some(Self::Sbom),
            _ => None,
        }
    }
}

/// The operation that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOperation {
    Added,
    Deleted,
}

impl ChangeOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Deleted => "deleted",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "added" => Some(Self::Added),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// A single change log entry read from the database.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangeEntry {
    pub cursor: Uuid,
    pub r#type: ChangeEntity,
    pub id: Option<Uuid>,
    pub operation: ChangeOperation,
}

/// Records a change event in the change_log table.
///
/// Called within the caller's transaction so the event is committed
/// atomically with the data change. The database trigger fires
/// `pg_notify` on commit.
pub async fn record_change(
    conn: &impl ConnectionTrait,
    entity_type: ChangeEntity,
    entity_id: Option<Uuid>,
    operation: ChangeOperation,
) -> Result<(), DbErr> {
    let id = Uuid::now_v7();
    conn.execute(Statement::from_sql_and_values(
        conn.get_database_backend(),
        "INSERT INTO change_log (id, entity_type, entity_id, operation) VALUES ($1, $2, $3, $4)",
        vec![
            id.into(),
            entity_type.as_str().into(),
            entity_id.into(),
            operation.as_str().into(),
        ],
    ))
    .await?;
    Ok(())
}

async fn fetch_latest_id(pool: &sqlx::PgPool) -> Uuid {
    let result: Result<Option<(Uuid,)>, _> =
        sqlx::query_as("SELECT id FROM change_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(pool)
            .await;
    match result {
        Ok(Some((id,))) => id,
        Ok(None) => Uuid::nil(),
        Err(err) => {
            tracing::warn!(%err, "failed to fetch latest change_log id");
            Uuid::nil()
        }
    }
}

async fn fetch_entries_after(
    pool: &sqlx::PgPool,
    cursor: &Uuid,
) -> Result<Vec<ChangeEntry>, anyhow::Error> {
    let rows: Vec<(Uuid, String, Option<Uuid>, String)> = sqlx::query_as(
        "SELECT id, entity_type, entity_id, operation FROM change_log WHERE id > $1 ORDER BY id",
    )
    .bind(cursor)
    .fetch_all(pool)
    .await?;

    let entries = rows
        .into_iter()
        .filter_map(|(cursor, r#type, id, operation)| {
            let r#type = ChangeEntity::from_str(&r#type)?;
            let operation = ChangeOperation::from_str(&operation)?;
            Some(ChangeEntry {
                cursor,
                r#type,
                id,
                operation,
            })
        })
        .collect();

    Ok(entries)
}

/// Watches the change_log table via PostgreSQL LISTEN/NOTIFY with
/// a periodic polling fallback. All sqlx types are encapsulated —
/// callers only interact through the public API.
pub struct ChangeListener {
    pool: sqlx::PgPool,
    poll_interval: Duration,
    cleanup_interval: Duration,
    retention: Duration,
}

impl ChangeListener {
    /// Creates a listener from a ReadWrite connection.
    ///
    /// Panics if the database backend is not PostgreSQL (checked at startup).
    pub fn new(db: &super::ReadWrite, retention: Duration) -> Result<Self, anyhow::Error> {
        let pool = db.get_postgres_connection_pool().clone();

        Ok(Self {
            pool,
            poll_interval: DEFAULT_POLL_INTERVAL,
            cleanup_interval: CLEANUP_INTERVAL,
            retention,
        })
    }

    /// Sets the polling interval for the fallback sweep.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Sets the interval between cleanup sweeps of old entries.
    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    /// Sets the retention period for cleaning old entries.
    pub fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = retention;
        self
    }

    /// Runs forever, calling `on_change` with batches of new entries.
    ///
    /// On startup, sets the cursor to the current maximum ID so only
    /// new events are delivered. Automatically reconnects the LISTEN
    /// connection on failure.
    pub async fn run<F>(self, on_change: F)
    where
        F: Fn(Vec<ChangeEntry>) + Send + 'static,
    {
        let mut cursor = self.fetch_max_id().await;
        tracing::info!(?cursor, "change listener starting");

        let mut last_cleanup = tokio::time::Instant::now();

        loop {
            match self
                .listen_loop(&on_change, &mut cursor, &mut last_cleanup)
                .await
            {
                Ok(()) => break,
                Err(err) => {
                    tracing::warn!(%err, "change listener connection lost, reconnecting in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Inner loop that creates a PgListener and processes events until an error occurs.
    async fn listen_loop<F>(
        &self,
        on_change: &F,
        cursor: &mut Uuid,
        last_cleanup: &mut tokio::time::Instant,
    ) -> Result<(), anyhow::Error>
    where
        F: Fn(Vec<ChangeEntry>) + Send + 'static,
    {
        let mut listener = sqlx::postgres::PgListener::connect_with(&self.pool).await?;
        listener.listen(CHANNEL).await?;
        tracing::info!("change listener connected and listening on '{CHANNEL}'");

        let mut poll_interval = tokio::time::interval(self.poll_interval);
        poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                notification = listener.recv() => {
                    match notification {
                        Ok(_) => {
                            self.sweep(on_change, cursor).await;
                        }
                        Err(err) => {
                            return Err(err.into());
                        }
                    }
                }
                _ = poll_interval.tick() => {
                    self.sweep(on_change, cursor).await;
                }
            }

            if last_cleanup.elapsed() >= self.cleanup_interval {
                self.cleanup().await;
                *last_cleanup = tokio::time::Instant::now();
            }
        }
    }

    /// Queries new change_log entries after the cursor and delivers them.
    async fn sweep<F>(&self, on_change: &F, cursor: &mut Uuid)
    where
        F: Fn(Vec<ChangeEntry>),
    {
        match self.fetch_after(cursor).await {
            Ok(entries) if entries.is_empty() => {}
            Ok(entries) => {
                if let Some(last) = entries.last() {
                    *cursor = last.cursor;
                }
                tracing::debug!(count = entries.len(), "delivering change events");
                on_change(entries);
            }
            Err(err) => {
                tracing::warn!(%err, "failed to sweep change_log");
            }
        }
    }

    async fn fetch_max_id(&self) -> Uuid {
        fetch_latest_id(&self.pool).await
    }

    async fn fetch_after(&self, cursor: &Uuid) -> Result<Vec<ChangeEntry>, anyhow::Error> {
        fetch_entries_after(&self.pool, cursor).await
    }

    /// Deletes change_log entries older than the retention period.
    async fn cleanup(&self) {
        let retention_secs = self.retention.as_secs() as i64;
        let result = sqlx::query(
            "DELETE FROM change_log WHERE created_at < NOW() - ($1 * INTERVAL '1 second')",
        )
        .bind(retention_secs)
        .execute(&self.pool)
        .await;

        match result {
            Ok(r) => {
                if r.rows_affected() > 0 {
                    tracing::debug!(
                        deleted = r.rows_affected(),
                        "cleaned up old change_log entries"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(%err, "failed to clean up change_log");
            }
        }
    }
}

/// Fan-out broadcaster for change events.
///
/// Wraps a single [`ChangeListener`] and distributes events to multiple
/// subscribers via [`tokio::sync::broadcast`]. Created once at startup.
#[derive(Clone)]
pub struct ChangeBroadcaster {
    tx: broadcast::Sender<ChangeEntry>,
    pool: sqlx::PgPool,
    _task: Arc<tokio::task::JoinHandle<()>>,
}

impl ChangeBroadcaster {
    pub fn new(
        db_rw: &super::ReadWrite,
        retention: Duration,
        poll_interval: Duration,
        cleanup_interval: Duration,
    ) -> Result<Self, anyhow::Error> {
        let pool = db_rw.get_postgres_connection_pool().clone();
        let (tx, _) = broadcast::channel(1024);
        let listener = ChangeListener::new(db_rw, retention)?
            .with_poll_interval(poll_interval)
            .with_cleanup_interval(cleanup_interval);
        let sender = tx.clone();

        let task = tokio::spawn(async move {
            listener
                .run(move |entries| {
                    for entry in entries {
                        let _ = sender.send(entry);
                    }
                })
                .await;
        });

        Ok(Self {
            tx,
            pool,
            _task: Arc::new(task),
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ChangeEntry> {
        self.tx.subscribe()
    }

    pub async fn fetch_latest_cursor(&self) -> Uuid {
        fetch_latest_id(&self.pool).await
    }

    pub async fn fetch_after(&self, cursor: &Uuid) -> Result<Vec<ChangeEntry>, anyhow::Error> {
        fetch_entries_after(&self.pool, cursor).await
    }
}
