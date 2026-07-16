mod load;

#[cfg(test)]
mod test;

use crate::{
    Error,
    config::CorrelationConfig,
    model::{CorrelationMatch, CorrelationState},
};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{Instrument, info_span, instrument};
use trustify_common::db::ReadOnly;
use uuid::Uuid;

/// Events that trigger state reloads in the background loader.
#[derive(Debug)]
pub enum CorrelationEvent {
    /// Advisory data changed — reload advisory index.
    AdvisoryChanged,
    /// An SBOM was ingested or updated.
    SbomIngested(Uuid),
    /// An SBOM was deleted.
    SbomDeleted(Uuid),
    /// Full reload of all data.
    Reload,
}

/// In-memory correlation service for fast advisory-SBOM matching.
#[derive(Clone)]
pub struct CorrelationService {
    state: Arc<ArcSwap<CorrelationState>>,
    _db: ReadOnly,
    tx: mpsc::UnboundedSender<CorrelationEvent>,
    _loader: Arc<JoinHandle<()>>,
}

impl CorrelationService {
    /// Creates and starts the correlation service, loading initial state from the database.
    pub async fn new(_config: &CorrelationConfig, db: ReadOnly) -> Result<Self, anyhow::Error> {
        let state = Arc::new(ArcSwap::from_pointee(CorrelationState::empty()));
        let (tx, rx) = mpsc::unbounded_channel();

        let loader_state = state.clone();
        let loader_db = db.clone();

        // Initial load
        let initial = load::load_all(&db)
            .instrument(info_span!("correlation initial load"))
            .await?;
        state.store(Arc::new(initial));

        let _loader = Arc::new(tokio::spawn(Self::background_loader(
            loader_state,
            loader_db,
            rx,
        )));

        Ok(Self {
            state,
            _db: db,
            tx,
            _loader,
        })
    }

    /// Returns the current correlation state for inspection.
    pub fn state(&self) -> arc_swap::Guard<Arc<CorrelationState>> {
        self.state.load()
    }

    /// Queues an event for the background loader to process.
    pub fn notify(&self, event: CorrelationEvent) {
        if self.tx.send(event).is_err() {
            tracing::warn!("correlation event channel closed");
        }
    }

    /// Finds all advisories that affect the given SBOM.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub fn correlate_sbom(&self, sbom_id: Uuid) -> Result<Vec<CorrelationMatch>, Error> {
        let state = self.state.load();

        let packages = state
            .sbom_index
            .by_sbom
            .get(&sbom_id)
            .ok_or_else(|| Error::SbomNotFound(sbom_id.to_string()))?;

        let sbom_cpes = state.sbom_index.describing_cpes.get(&sbom_id);
        let sbom_has_cpes = sbom_cpes.is_some_and(|c| !c.is_empty());
        let mut matches = Vec::new();

        for pkg in packages {
            // Path 1: purl_status matching (version range based)
            if let Some(statuses) = state.advisory_index.by_base_purl.get(&pkg.base_purl_id) {
                for entry in statuses {
                    if state
                        .advisory_index
                        .deprecated_advisories
                        .contains(&entry.advisory_id)
                    {
                        continue;
                    }

                    if !check_cpe_context(entry.context_cpe_id, sbom_cpes, sbom_has_cpes) {
                        continue;
                    }

                    if crate::model::version::version_matches(&pkg.version, &entry.version_range) {
                        matches.push(CorrelationMatch {
                            advisory_id: entry.advisory_id,
                            vulnerability_id: entry.vulnerability_id.clone(),
                            status_id: entry.status_id,
                            context_cpe_id: entry.context_cpe_id,
                            base_purl_id: pkg.base_purl_id,
                            version: pkg.version.clone(),
                        });
                    }
                }
            }

            // Path 2: product_status matching (name based)
            // Match by simple name
            Self::check_product_status(
                &state,
                &pkg.name,
                pkg,
                sbom_cpes,
                sbom_has_cpes,
                &mut matches,
            );
            // Match by namespace/name
            if let Some(ns) = &pkg.namespace {
                let full_name = format!("{}/{}", ns, pkg.name);
                Self::check_product_status(
                    &state,
                    &full_name,
                    pkg,
                    sbom_cpes,
                    sbom_has_cpes,
                    &mut matches,
                );
            }
        }

        Ok(matches)
    }

    /// Checks product_status entries for a package name match.
    fn check_product_status(
        state: &CorrelationState,
        package_name: &str,
        pkg: &crate::model::SbomPackageEntry,
        sbom_cpes: Option<&std::collections::HashSet<Uuid>>,
        sbom_has_cpes: bool,
        matches: &mut Vec<CorrelationMatch>,
    ) {
        if let Some(entries) = state.advisory_index.product_by_name.get(package_name) {
            for entry in entries {
                if state
                    .advisory_index
                    .deprecated_advisories
                    .contains(&entry.advisory_id)
                {
                    continue;
                }

                if !check_cpe_context(entry.context_cpe_id, sbom_cpes, sbom_has_cpes) {
                    continue;
                }

                matches.push(CorrelationMatch {
                    advisory_id: entry.advisory_id,
                    vulnerability_id: entry.vulnerability_id.clone(),
                    status_id: entry.status_id,
                    context_cpe_id: entry.context_cpe_id,
                    base_purl_id: pkg.base_purl_id,
                    version: pkg.version.clone(),
                });
            }
        }
    }

    /// Background task that processes events and reloads state.
    async fn background_loader(
        state: Arc<ArcSwap<CorrelationState>>,
        db: ReadOnly,
        mut rx: mpsc::UnboundedReceiver<CorrelationEvent>,
    ) {
        while let Some(event) = rx.recv().await {
            tracing::info!(?event, "processing correlation event");

            // Coalesce: drain any pending events before reloading
            while rx.try_recv().is_ok() {}

            match load::load_all(&db)
                .instrument(info_span!("correlation reload"))
                .await
            {
                Ok(new_state) => {
                    state.store(Arc::new(new_state));
                    tracing::info!("correlation state reloaded");
                }
                Err(err) => {
                    tracing::error!(%err, "failed to reload correlation state");
                }
            }
        }
    }
}

/// Checks the CPE context filter, matching the v3 SQL logic:
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
