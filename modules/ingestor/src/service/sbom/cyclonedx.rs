use crate::{
    graph::{Graph, Outcome, sbom::cyclonedx},
    model::IngestResult,
    service::{Error, Warnings},
};
use sea_orm::TransactionTrait;
use serde_cyclonedx::cyclonedx::v_1_6::Component;
use std::str::FromStr;
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id};
use trustify_entity::labels::Labels;

pub struct CyclonedxLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CyclonedxLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: Labels,
        buffer: &[u8],
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::default();

        let cdx: Box<serde_cyclonedx::cyclonedx::v_1_6::CycloneDx> = serde_json::from_slice(buffer)
            .map_err(|err| Error::UnsupportedFormat(format!("Failed to parse: {err}")))?;

        let labels_updated = extract_labels(cdx.components.as_ref(), labels);

        log::info!(
            "Storing - version: {:?}, serialNumber: {:?}",
            cdx.version,
            cdx.serial_number,
        );

        let tx = self.graph.db.begin().await?;

        let document_id = cdx
            .serial_number
            .clone()
            .map(|sn| format!("{}/{}", sn, cdx.version.unwrap_or(0)))
            .or_else(|| {
                cdx.version.map(|v| v.to_string()) // If serial_number is None, just use version
            });

        let ctx = match self
            .graph
            .ingest_sbom(
                labels_updated,
                digests,
                document_id.clone(),
                cyclonedx::Information(&cdx),
                &tx,
            )
            .await?
        {
            Outcome::Existed(sbom) => sbom,
            Outcome::Added(sbom) => {
                sbom.ingest_cyclonedx(cdx, &warnings, &tx).await?;
                tx.commit().await?;

                sbom
            }
        };

        Ok(IngestResult {
            id: Id::Uuid(ctx.sbom.sbom_id),
            document_id,
            warnings: warnings.into(),
        })
    }
}

enum Kind {
    AIBom,
    CBom,
}

impl Kind {
    fn as_str(&self) -> &'static str {
        match self {
            Kind::AIBom => "aibom",
            Kind::CBom => "cbom",
        }
    }
}

impl FromStr for Kind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "machine-learning-model" => Ok(Kind::AIBom),
            "cryptographic-asset" => Ok(Kind::CBom),
            _ => Err(()),
        }
    }
}

fn extract_labels(components: Option<&Vec<Component>>, labels_in: Labels) -> Labels {
    let mut labels = Labels::new().add("type", "cyclonedx");

    if let Some(components) = components {
        for component in components {
            if let Ok(kind) = Kind::from_str(&component.type_) {
                labels = labels.add("kind", kind.as_str());
            }
        }
    }

    if !labels_in.is_empty() {
        return labels.extend(labels_in.0);
    }

    labels
}

#[cfg(test)]
mod test {
    use crate::service::{Cache, IngestorService};
    use crate::{graph::Graph, service::Format};
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::{TrustifyContext, document_bytes};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let data = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ingestor
            .ingest(
                &data,
                Format::CycloneDX,
                ("source", "test"),
                None,
                Cache::Skip,
            )
            .await
            .expect("must ingest");

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_ai_cyclonedx_nvidia(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let data = document_bytes("cyclonedx/ai/nvidia_canary-1b-v2_aibom.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ingestor
            .ingest(
                &data,
                Format::CycloneDX,
                [("type", "cyclonedx"), ("kind", "aibom")],
                None,
                Cache::Skip,
            )
            .await
            .expect("must ingest");

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_ai_cyclonedx_ibm(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let data =
            document_bytes("cyclonedx/ai/ibm-granite_granite-docling-258M_aibom.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ingestor
            .ingest(
                &data,
                Format::CycloneDX,
                [("type", "cyclonedx"), ("kind", "aibom")],
                None,
                Cache::Skip,
            )
            .await
            .expect("must ingest");

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_cryptographic_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let data = document_bytes("cyclonedx/cryptographic/cbom.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ingestor
            .ingest(
                &data,
                Format::CycloneDX,
                [("type", "cyclonedx"), ("kind", "cbom")],
                None,
                Cache::Skip,
            )
            .await
            .expect("must ingest");

        Ok(())
    }
}
