use crate::{
    graph::{Graph, Outcome, sbom::clearly_defined::Curation},
    model::IngestResult,
    service::Error,
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::labels::Labels;

pub struct ClearlyDefinedCurationLoader<'g> {
    graph: &'g Graph,
}

impl<'g> ClearlyDefinedCurationLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, curation, tx), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: Labels,
        curation: Curation,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let sbom = match self
            .graph
            .ingest_sbom(labels, digests, Some(curation.document_id()), &curation, tx)
            .await?
        {
            Outcome::Existed(sbom) => sbom,
            Outcome::Added(sbom) => {
                sbom.ingest_clearly_defined_curation(curation, tx)
                    .await
                    .map_err(Error::Generic)?;

                sbom
            }
        };

        Ok(IngestResult {
            id: sbom.sbom.sbom_id.to_string(),
            document_id: sbom.sbom.document_id,
            warnings: vec![],
        })
    }
}

#[cfg(test)]
mod test {
    use crate::graph::Graph;
    use crate::service::{Cache, Format, IngestorService};
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;
    use trustify_test_context::document_bytes;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_clearly_defined(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());
        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        let data = document_bytes("clearly-defined/chrono.yaml").await?;

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::ClearlyDefinedCuration,
                        ("source", "test"),
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        Ok(())
    }
}
