use crate::{
    graph::{
        Graph, Outcome,
        sbom::spdx::{self},
    },
    model::IngestResult,
    service::{Error, Warnings},
};
use sea_orm::TransactionTrait;
use serde_json::Value;
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id, sbom::spdx::parse_spdx};
use trustify_entity::labels::Labels;

pub struct SpdxLoader<'g> {
    graph: &'g Graph,
}

impl<'g> SpdxLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: Labels,
        json: Value,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::default();

        let (spdx, _) = parse_spdx(&warnings, json)?;

        log::info!(
            "Storing: {}",
            spdx.document_creation_information.document_name
        );

        let tx = self.graph.db.begin().await?;

        let labels = labels.add("type", "spdx");

        let document_id = spdx
            .document_creation_information
            .spdx_document_namespace
            .clone();

        let sbom = match self
            .graph
            .ingest_sbom(
                labels,
                digests,
                Some(document_id.clone()),
                spdx::Information(&spdx),
                &tx,
            )
            .await?
        {
            Outcome::Existed(sbom) => sbom,
            Outcome::Added(sbom) => {
                sbom.ingest_spdx(spdx, &warnings, &tx).await?;
                tx.commit().await?;
                sbom
            }
        };

        Ok(IngestResult {
            id: Id::Uuid(sbom.sbom.sbom_id),
            document_id: Some(document_id),
            warnings: warnings.into(),
        })
    }
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
    async fn ingest_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());
        let data = document_bytes("ubi9-9.2-755.1697625012.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ingestor
            .ingest(&data, Format::SPDX, ("source", "test"), None, Cache::Skip)
            .await
            .expect("must ingest");

        Ok(())
    }
}
