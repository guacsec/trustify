use async_graphql::{Context, FieldError, FieldResult, Object};
use std::sync::Arc;
use trustify_common::db::Database;
use trustify_entity::{labels::Labels, sbom::Model as Sbom};
use trustify_module_ingestor::graph::Graph;
use uuid::Uuid;

#[derive(Default)]
pub struct SbomQuery;

#[Object]
impl SbomQuery {
    async fn get_sbom_by_id(&self, ctx: &Context<'_>, id: Uuid) -> FieldResult<Sbom> {
        let db = ctx.data::<Arc<Database>>()?;
        let graph = ctx.data::<Arc<Graph>>()?;
        let sbom = graph.locate_sbom_by_id(id, db.as_ref()).await;

        match sbom {
            Ok(Some(sbom_context)) => Ok(Sbom {
                sbom_id: sbom_context.sbom.sbom_id,
                node_id: sbom_context.sbom.node_id,
                labels: sbom_context.sbom.labels,
                document_id: sbom_context.sbom.document_id,
                published: sbom_context.sbom.published,
                authors: sbom_context.sbom.authors,
                suppliers: sbom_context.sbom.suppliers,
                source_document_id: sbom_context.sbom.source_document_id,
                data_licenses: sbom_context.sbom.data_licenses,
                properties: sbom_context.sbom.properties,
            }),
            Ok(None) => Err(FieldError::new("SBOM not found")),
            Err(err) => Err(FieldError::from(err)),
        }
    }

    async fn get_sboms_by_labels(
        &self,
        ctx: &Context<'_>,
        labels: String,
    ) -> FieldResult<Vec<Sbom>> {
        let db = ctx.data::<Arc<Database>>()?;
        let graph = ctx.data::<Arc<Graph>>()?;

        let mut local_labels = Labels::new();
        let labs = labels.split(',');
        for item in labs {
            let mut label = item.split(':');
            local_labels.insert(
                label.next().unwrap_or("").split_whitespace().collect(),
                label.next().unwrap_or("").split_whitespace().collect(),
            );
        }

        let sboms = graph
            .locate_sboms_by_labels(local_labels, db.as_ref())
            .await
            .unwrap_or_default();

        sboms
            .into_iter()
            .map(|sbom| {
                Ok(Sbom {
                    sbom_id: sbom.sbom.sbom_id,
                    node_id: sbom.sbom.node_id,
                    labels: sbom.sbom.labels,
                    document_id: sbom.sbom.document_id,
                    published: sbom.sbom.published,
                    authors: sbom.sbom.authors,
                    suppliers: sbom.sbom.suppliers,
                    source_document_id: sbom.sbom.source_document_id,
                    data_licenses: sbom.sbom.data_licenses,
                    properties: sbom.sbom.properties,
                })
            })
            .collect()
    }
}
