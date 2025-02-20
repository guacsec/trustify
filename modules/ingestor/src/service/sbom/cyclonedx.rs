use crate::{
    graph::{sbom::cyclonedx, Graph, Outcome},
    model::IngestResult,
    service::Error,
};
use sea_orm::TransactionTrait;
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

    #[instrument(skip(self, buffer), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: Labels,
        buffer: &[u8],
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let cdx: serde_cyclonedx::cyclonedx::v_1_6::CycloneDx = serde_json::from_slice(buffer)
            .map_err(|err| Error::UnsupportedFormat(format!("Failed to parse: {err}")))?;

        let labels = labels.add("type", "cyclonedx");

        log::info!(
            "Storing - version: {:?}, serialNumber: {:?}",
            cdx.version,
            cdx.serial_number,
        );

        let tx = self.graph.db.begin().await?;

        let document_id = cdx
            .serial_number
            .clone()
            .or_else(|| cdx.version.map(|v| v.to_string()));

        let ctx = match self
            .graph
            .ingest_sbom(
                labels,
                digests,
                document_id.clone(),
                cyclonedx::Information(&cdx),
                &tx,
            )
            .await?
        {
            Outcome::Existed(sbom) => sbom,
            Outcome::Added(sbom) => {
                sbom.ingest_cyclonedx(cdx, &tx)
                    .await
                    .map_err(Error::Generic)?;
                tx.commit().await?;

                sbom
            }
        };

        Ok(IngestResult {
            id: Id::Uuid(ctx.sbom.sbom_id),
            document_id,
            warnings: vec![],
        })
    }
}

#[cfg(test)]
mod test {
    use crate::service::IngestorService;
    use crate::{graph::Graph, service::Format};
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::{document_bytes, TrustifyContext};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let data = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ingestor
            .ingest(&data, Format::CycloneDX, ("source", "test"), None)
            .await
            .expect("must ingest");

        Ok(())
    }
}
