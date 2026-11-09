use crate::{
    graph::{
        Graph, Outcome,
        sbom::spdx::{self},
    },
    model::IngestResult,
    service::{Error, Warnings},
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde_json::Value;
use spdx_rs::models::SPDX;
use tracing::instrument;
use trustify_common::{hashing::Digests, sbom::spdx::parse_spdx};
use trustify_entity::labels::Labels;

/// A parsed SPDX document, and what had to be fixed to parse it.
#[derive(Clone, Debug)]
pub struct SpdxDocument {
    pub sbom: SPDX,
    /// The license expressions which were replaced, as they aren't valid.
    pub warnings: Vec<String>,
}

impl SpdxDocument {
    /// Parse a SPDX document, replacing invalid license expressions.
    pub fn parse(json: Value) -> Result<Self, serde_json::Error> {
        let warnings = Warnings::new();
        let (sbom, _) = parse_spdx(&warnings, json)?;
        Ok(Self {
            sbom,
            warnings: warnings.into(),
        })
    }
}

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
        document: SpdxDocument,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let SpdxDocument {
            sbom: spdx,
            warnings: parse_warnings,
        } = document;
        let warnings = Warnings::default();
        for warning in parse_warnings {
            warnings.add(warning);
        }

        tracing::info!(
            "Storing: {}",
            spdx.document_creation_information.document_name
        );

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
                tx,
            )
            .await?
        {
            Outcome::Existed(sbom) => {
                return Ok(IngestResult {
                    id: sbom.sbom.sbom_id.to_string(),
                    document_id: Some(document_id),
                    duplicate: true,
                    warnings: warnings.into(),
                    validation: Vec::new(),
                });
            }
            Outcome::Added(sbom) => {
                sbom.ingest_spdx(spdx, &warnings, tx).await?;
                sbom
            }
        };

        Ok(IngestResult {
            id: sbom.sbom.sbom_id.to_string(),
            document_id: Some(document_id),
            warnings: warnings.into(),
            duplicate: false,
            validation: Vec::new(),
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
        let graph = Graph::new();
        let data = document_bytes("ubi9-9.2-755.1697625012.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::SPDX,
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
