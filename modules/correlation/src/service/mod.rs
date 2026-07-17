pub mod hydrate;
mod load;

#[cfg(test)]
mod test;

use crate::{
    Error,
    config::CorrelationConfig,
    model::{AdvisoryIndex, CorrelationMatch, CorrelationState, PurlKey, SbomIndex},
};
use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{Instrument, info_span, instrument};
use trustify_common::db::change::ChangeListener;
use trustify_common::db::{ReadOnly, ReadWrite, change::ChangeEntity};
use uuid::Uuid;

/// Events that trigger incremental state updates in the background loader.
#[derive(Debug)]
pub enum CorrelationEvent {
    /// A specific advisory was ingested, updated, or deleted.
    AdvisoryChanged(Uuid),
    /// A specific SBOM was ingested, updated, or deleted.
    SbomChanged(Uuid),
}

/// In-memory correlation service for fast advisory-SBOM matching.
///
/// Advisory and SBOM indexes are stored in separate `ArcSwap` instances so that
/// incremental updates only clone the index that changed.
#[derive(Clone)]
pub struct CorrelationService {
    advisory_state: Arc<ArcSwap<AdvisoryIndex>>,
    sbom_state: Arc<ArcSwap<SbomIndex>>,
    _db: ReadOnly,
    tx: mpsc::UnboundedSender<CorrelationEvent>,
    _loader: Arc<JoinHandle<()>>,
    _listener: Arc<JoinHandle<()>>,
}

impl CorrelationService {
    /// Creates and starts the correlation service, loading initial state from the database.
    ///
    /// The `db_rw` parameter provides the PostgreSQL connection for LISTEN/NOTIFY;
    /// it fails fast at startup if the backend is not PostgreSQL.
    pub async fn new(
        config: &CorrelationConfig,
        db_ro: ReadOnly,
        db_rw: &ReadWrite,
    ) -> Result<Self, anyhow::Error> {
        let (tx, rx) = mpsc::unbounded_channel();

        // Initial full load
        let initial = load::load_all(&db_ro)
            .instrument(info_span!("correlation initial load"))
            .await?;

        tracing::info!("correlation service initial load complete");

        let advisory_state = Arc::new(ArcSwap::from_pointee(initial.advisory_index));
        let sbom_state = Arc::new(ArcSwap::from_pointee(initial.sbom_index));

        let loader_advisory = advisory_state.clone();
        let loader_sbom = sbom_state.clone();
        let loader_db = db_ro.clone();

        let debounce = Duration::from_secs(config.correlation_debounce_secs);
        let _loader = Arc::new(tokio::spawn(Self::background_loader(
            loader_advisory,
            loader_sbom,
            loader_db,
            rx,
            debounce,
        )));

        // Spawn the change listener (LISTEN/NOTIFY + polling fallback)
        let change_listener = ChangeListener::new(db_rw)?;
        let poll_interval = Duration::from_secs(config.correlation_poll_interval_secs);
        let listener_tx = tx.clone();

        let _listener = Arc::new(tokio::spawn(async move {
            change_listener
                .with_poll_interval(poll_interval)
                .run(move |entries| {
                    for entry in entries {
                        if let Some(entity_id) = entry.entity_id {
                            let event = match entry.entity_type {
                                ChangeEntity::Advisory => {
                                    CorrelationEvent::AdvisoryChanged(entity_id)
                                }
                                ChangeEntity::Sbom => CorrelationEvent::SbomChanged(entity_id),
                            };
                            let _ = listener_tx.send(event);
                        }
                    }
                })
                .await;
        }));

        Ok(Self {
            advisory_state,
            sbom_state,
            _db: db_ro,
            tx,
            _loader,
            _listener,
        })
    }

    /// Returns the current correlation state for inspection.
    pub fn state(&self) -> CorrelationState {
        let advisory_index = self.advisory_state.load();
        let sbom_index = self.sbom_state.load();
        CorrelationState {
            advisory_index: (**advisory_index).clone(),
            sbom_index: (**sbom_index).clone(),
        }
    }

    /// Sends a local event (for tests or manual triggers).
    pub fn notify_local(&self, event: CorrelationEvent) {
        if self.tx.send(event).is_err() {
            tracing::warn!("correlation event channel closed");
        }
    }

    /// Returns the current advisory status slug map (status_id → slug).
    pub fn status_slugs(&self) -> HashMap<Uuid, Arc<str>> {
        self.advisory_state.load().statuses.clone()
    }

    /// Finds all advisories that affect the given SBOM.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub fn correlate_sbom(&self, sbom_id: Uuid) -> Result<Vec<CorrelationMatch>, Error> {
        let advisory = self.advisory_state.load();
        let sbom = self.sbom_state.load();

        let package_indices = sbom
            .by_sbom
            .get(&sbom_id)
            .ok_or_else(|| Error::SbomNotFound(sbom_id.to_string()))?;

        let sbom_cpes = sbom.describing_cpes.get(&sbom_id);
        let sbom_has_cpes = sbom_cpes.is_some_and(|c| !c.is_empty());
        let has_product_index = !advisory.product_by_name.is_empty();
        let mut matches = Vec::with_capacity(package_indices.len());

        for &idx in package_indices.iter() {
            let pkg = sbom.catalog.get(idx);
            let key = PurlKey {
                ty: Arc::clone(&pkg.ty),
                namespace: pkg.namespace.as_ref().map(Arc::clone),
                name: Arc::clone(&pkg.name),
            };

            // Path 1: purl_status matching (version range based)
            if let Some(statuses) = advisory.by_purl.get(&key) {
                for entry in statuses {
                    if !check_cpe_context(entry.context_cpe_id, sbom_cpes, sbom_has_cpes) {
                        continue;
                    }

                    if crate::model::version::version_matches(&pkg.version, &entry.version_range) {
                        matches.push(CorrelationMatch {
                            advisory_id: entry.advisory_id,
                            vulnerability_id: Arc::clone(&entry.vulnerability_id),
                            status_id: entry.status_id,
                            context_cpe_id: entry.context_cpe_id,
                            purl_key: key.clone(),
                            version: Arc::clone(&pkg.version),
                        });
                    }
                }
            }

            // Path 2: product_status matching (name based)
            if has_product_index {
                Self::check_product_status(
                    &advisory,
                    &pkg.name,
                    &key,
                    &pkg.version,
                    sbom_cpes,
                    sbom_has_cpes,
                    &mut matches,
                );
                if let Some(ns) = &pkg.namespace {
                    let full_name = format!("{}/{}", ns, pkg.name);
                    Self::check_product_status(
                        &advisory,
                        &full_name,
                        &key,
                        &pkg.version,
                        sbom_cpes,
                        sbom_has_cpes,
                        &mut matches,
                    );
                }
            }
        }

        Ok(matches)
    }

    /// Checks product_status entries for a package name match.
    fn check_product_status(
        advisory: &AdvisoryIndex,
        package_name: &str,
        purl_key: &PurlKey,
        version: &Arc<str>,
        sbom_cpes: Option<&std::collections::HashSet<Uuid>>,
        sbom_has_cpes: bool,
        matches: &mut Vec<CorrelationMatch>,
    ) {
        if let Some(entries) = advisory.product_by_name.get(package_name) {
            for entry in entries {
                if !check_cpe_context(entry.context_cpe_id, sbom_cpes, sbom_has_cpes) {
                    continue;
                }

                matches.push(CorrelationMatch {
                    advisory_id: entry.advisory_id,
                    vulnerability_id: Arc::clone(&entry.vulnerability_id),
                    status_id: entry.status_id,
                    context_cpe_id: entry.context_cpe_id,
                    purl_key: purl_key.clone(),
                    version: Arc::clone(version),
                });
            }
        }
    }

    /// Background task that processes events with debouncing and applies incremental updates.
    async fn background_loader(
        advisory_state: Arc<ArcSwap<AdvisoryIndex>>,
        sbom_state: Arc<ArcSwap<SbomIndex>>,
        db: ReadOnly,
        mut rx: mpsc::UnboundedReceiver<CorrelationEvent>,
        debounce: Duration,
    ) {
        while let Some(event) = rx.recv().await {
            // Debounce: wait then drain accumulated events
            let mut pending = PendingChanges::new();
            pending.add(event);

            tokio::time::sleep(debounce).await;
            while let Ok(event) = rx.try_recv() {
                pending.add(event);
            }

            tracing::info!(
                advisories = pending.advisory_ids.len(),
                sboms = pending.sbom_ids.len(),
                "applying incremental correlation updates"
            );

            if let Err(err) = Self::apply_changes(&advisory_state, &sbom_state, &db, &pending).await
            {
                tracing::error!(%err, "failed to apply incremental correlation updates");
            }
        }
    }

    /// Loads patches for the changed entities and applies them to the state.
    ///
    /// Only clones the index that actually has changes, avoiding unnecessary
    /// deep-clones of the unaffected side.
    async fn apply_changes(
        advisory_state: &ArcSwap<AdvisoryIndex>,
        sbom_state: &ArcSwap<SbomIndex>,
        db: &ReadOnly,
        pending: &PendingChanges,
    ) -> Result<(), anyhow::Error> {
        let txn = db.begin().await?;

        // Apply advisory patches — only clone advisory index if needed
        if !pending.advisory_ids.is_empty() {
            let ids: Vec<Uuid> = pending.advisory_ids.iter().copied().collect();
            let mut patches = load::load_advisory_patches(&ids, &txn)
                .instrument(info_span!("load advisory patches"))
                .await?;

            let old = advisory_state.load();
            let mut new_advisory = (**old).clone();
            for &id in &ids {
                let patch = patches.remove(&id).unwrap_or_default();
                new_advisory.apply_patch(id, patch);
            }
            advisory_state.store(Arc::new(new_advisory));
        }

        // Apply SBOM patches — only clone sbom index if needed
        if !pending.sbom_ids.is_empty() {
            let ids: Vec<Uuid> = pending.sbom_ids.iter().copied().collect();
            let mut patches = load::load_sbom_patches(&ids, &txn)
                .instrument(info_span!("load sbom patches"))
                .await?;

            let old = sbom_state.load();
            let mut new_sbom = (**old).clone();
            for &id in &ids {
                let patch = patches.remove(&id).unwrap_or_default();
                new_sbom.apply_patch(id, patch);
            }
            sbom_state.store(Arc::new(new_sbom));
        }

        tracing::info!("correlation state updated incrementally");
        Ok(())
    }
}

/// Accumulates changed entity IDs during the debounce window.
struct PendingChanges {
    advisory_ids: HashSet<Uuid>,
    sbom_ids: HashSet<Uuid>,
}

impl PendingChanges {
    fn new() -> Self {
        Self {
            advisory_ids: HashSet::new(),
            sbom_ids: HashSet::new(),
        }
    }

    fn add(&mut self, event: CorrelationEvent) {
        match event {
            CorrelationEvent::AdvisoryChanged(id) => {
                self.advisory_ids.insert(id);
            }
            CorrelationEvent::SbomChanged(id) => {
                self.sbom_ids.insert(id);
            }
        }
    }
}

/// Checks the CPE context filter, matching the v3a SQL logic:
/// - NULL context_cpe_id always matches
/// - If the SBOM has no describing CPEs, everything matches
/// - Otherwise the context_cpe_id must be in the SBOM's CPE set
fn check_cpe_context(
    context_cpe_id: Option<Uuid>,
    sbom_cpes: Option<&std::collections::HashSet<Uuid>>,
    sbom_has_cpes: bool,
) -> bool {
    match context_cpe_id {
        None => true,
        Some(cpe_id) => {
            if !sbom_has_cpes {
                return true;
            }
            sbom_cpes.is_some_and(|cpes| cpes.contains(&cpe_id))
        }
    }
}
