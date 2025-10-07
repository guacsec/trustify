use crate::{
    graph::{Graph, Outcome, sbom::SbomInformation},
    model::IngestResult,
    service::Error,
};
use anyhow::anyhow;
use hex::ToHex;
use jsonpath_rust::JsonPath;
use sea_orm::{EntityTrait, TransactionTrait};
use trustify_common::{
    hashing::Digests,
    id::{Id, TrySelectForId},
};
use trustify_entity::{labels::Labels, sbom};

pub struct ClearlyDefinedLoader<'g> {
    graph: &'g Graph,
}

impl<'g> ClearlyDefinedLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load(
        &self,
        labels: Labels,
        item: serde_json::Value,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        if let Ok(Some(previously_found)) = sbom::Entity::find()
            .try_filter(Id::Sha512(digests.sha512.encode_hex()))?
            .one(&self.graph.db)
            .await
        {
            // we already have ingested this document, skip to my lou.
            return Ok(IngestResult {
                id: Id::Uuid(previously_found.sbom_id),
                document_id: previously_found.document_id,
                warnings: vec![],
            });
        }

        let document_id = item
            .query("$._id")?
            .first()
            .and_then(|inner| inner.as_str());
        let license = item
            .query("$.licensed.declared")?
            .first()
            .and_then(|inner| inner.as_str());

        if let Some(document_id) = document_id {
            let tx = self.graph.db.begin().await?;

            let sbom = match self
                .graph
                .ingest_sbom(
                    labels,
                    digests,
                    Some(document_id.to_string()),
                    SbomInformation {
                        node_id: document_id.to_string(),
                        name: document_id.to_string(),
                        published: None,
                        authors: vec!["ClearlyDefined Definitions".to_string()],
                        suppliers: vec![],
                        data_licenses: vec![],
                        properties: Default::default(),
                    },
                    &tx,
                )
                .await?
            {
                Outcome::Existed(sbom) => sbom,
                Outcome::Added(sbom) => {
                    if let Some(license) = license {
                        sbom.ingest_purl_license_assertion(license, &tx).await?;
                    }

                    tx.commit().await?;

                    sbom
                }
            };

            Ok(IngestResult {
                id: Id::Uuid(sbom.sbom.sbom_id),
                document_id: sbom.sbom.document_id,
                warnings: vec![],
            })
        } else {
            Err(Error::Generic(anyhow!("No valid information")))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::graph::Graph;
    use crate::service::{Cache, Error, Format, IngestorService};
    use anyhow::anyhow;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::purl::Purl;
    use trustify_test_context::TrustifyContext;
    use trustify_test_context::document_bytes;

    fn coordinates_to_purl(coords: &str) -> Result<Purl, Error> {
        let parts = coords.split('/').collect::<Vec<_>>();

        if parts.len() != 5 {
            return Err(Error::Generic(anyhow!(
                "Unable to derive pURL from {}",
                coords
            )));
        }

        Ok(Purl {
            ty: parts[0].to_string(),
            namespace: if parts[2] == "-" {
                None
            } else {
                Some(parts[2].to_string())
            },
            name: parts[3].to_string(),
            version: Some(parts[4].to_string()),
            qualifiers: Default::default(),
        })
    }

    #[test]
    fn coords_conversion_no_namespace() {
        let coords = "nuget/nuget/-/microsoft.aspnet.mvc/4.0.40804";

        let purl = coordinates_to_purl(coords);

        assert!(purl.is_ok());

        let purl = purl.unwrap();

        assert_eq!("nuget", purl.ty);
        assert_eq!(None, purl.namespace);
        assert_eq!("microsoft.aspnet.mvc", purl.name);
        assert_eq!(Some("4.0.40804".to_string()), purl.version);
    }

    #[test]
    fn coords_conversion_with_namespace() {
        let coords = "npm/npm/@tacobell/taco/1.2.3";

        let purl = coordinates_to_purl(coords);

        assert!(purl.is_ok());

        let purl = purl.unwrap();

        assert_eq!("npm", purl.ty);
        assert_eq!(Some("@tacobell".to_string()), purl.namespace);
        assert_eq!("taco", purl.name);
        assert_eq!(Some("1.2.3".to_string()), purl.version);
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_clearly_defined(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());
        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        let data = document_bytes("clearly-defined/aspnet.mvc-4.0.40804.json").await?;

        ingestor
            .ingest(
                &data,
                Format::ClearlyDefined,
                ("source", "test"),
                None,
                Cache::Skip,
            )
            .await
            .expect("must ingest");

        Ok(())
    }
}
