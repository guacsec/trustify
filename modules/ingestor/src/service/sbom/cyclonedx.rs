use crate::{
    graph::{Graph, Outcome, sbom::cyclonedx},
    model::IngestResult,
    service::{Error, Warnings},
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde_cyclonedx::cyclonedx::v_1_6::Component;
use std::str::FromStr;
use tracing::instrument;
use trustify_common::hashing::Digests;
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
        tx: &(impl ConnectionTrait + TransactionTrait),
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
                tx,
            )
            .await?
        {
            Outcome::Existed(sbom) => sbom,
            Outcome::Added(sbom) => {
                sbom.ingest_cyclonedx(cdx, &warnings, tx).await?;

                sbom
            }
        };

        Ok(IngestResult {
            id: ctx.sbom.sbom_id.to_string(),
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
    use sea_orm::EntityTrait;
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::sbom_ai;
    use trustify_entity::sbom_crypto;
    use trustify_test_context::{TrustifyContext, document_bytes};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let data = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::CycloneDX,
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

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_ai_cyclonedx_nvidia(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let data = document_bytes("cyclonedx/ai/nvidia_canary-1b-v2_aibom.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        assert_eq!(0, sbom_ai::Entity::find().all(&ctx.db).await?.len());

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::CycloneDX,
                        [("type", "cyclonedx"), ("kind", "aibom")],
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        assert_eq!(1, sbom_ai::Entity::find().all(&ctx.db).await?.len());

        // ensure ingestion is idempotent
        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::CycloneDX,
                        [("type", "cyclonedx"), ("kind", "aibom")],
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        assert_eq!(1, sbom_ai::Entity::find().all(&ctx.db).await?.len());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_ai_cyclonedx_ibm(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let data =
            document_bytes("cyclonedx/ai/ibm-granite_granite-docling-258M_aibom.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::CycloneDX,
                        [("type", "cyclonedx"), ("kind", "aibom")],
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_ai_cyclonedx_nvidia_properties(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let data = document_bytes("cyclonedx/ai/nvidia_canary-1b-v2_aibom.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::CycloneDX,
                        [("type", "cyclonedx"), ("kind", "aibom")],
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        let models = sbom_ai::Entity::find().all(&ctx.db).await?;
        assert_eq!(1, models.len());

        let props = &models[0].properties;

        // Generic properties take precedence over structured model_parameters.task
        // modelParameters.task = "text-generation" but generic property primaryPurpose = "automatic-speech-recognition"
        assert_eq!(
            props.get("primaryPurpose").and_then(|v| v.as_str()),
            Some("automatic-speech-recognition"),
        );

        // typeOfModel comes from generic properties (no structured approach.type_ in fixture)
        assert_eq!(
            props.get("typeOfModel").and_then(|v| v.as_str()),
            Some("transformer"),
        );

        // limitation comes from generic properties (no structured considerations in fixture)
        assert!(props.get("limitation").and_then(|v| v.as_str()).is_some(),);

        // Other generic properties are also present
        assert_eq!(
            props.get("bomFormat").and_then(|v| v.as_str()),
            Some("CycloneDX"),
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_ai_cyclonedx_ibm_properties(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let data =
            document_bytes("cyclonedx/ai/ibm-granite_granite-docling-258M_aibom.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::CycloneDX,
                        [("type", "cyclonedx"), ("kind", "aibom")],
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        let models = sbom_ai::Entity::find().all(&ctx.db).await?;
        assert_eq!(1, models.len());

        let props = &models[0].properties;

        // Generic property overrides structured model_parameters.task
        // modelParameters.task = "text-generation" but generic property primaryPurpose = "image-text-to-text"
        assert_eq!(
            props.get("primaryPurpose").and_then(|v| v.as_str()),
            Some("image-text-to-text"),
        );

        // typeOfModel from generic properties
        assert_eq!(
            props.get("typeOfModel").and_then(|v| v.as_str()),
            Some("idefics3"),
        );

        // IBM fixture has no limitation property
        assert!(props.get("limitation").is_none());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_ai_cyclonedx_structured_fields(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let data = document_bytes("cyclonedx/ai/test_structured_model_card.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::CycloneDX,
                        [("type", "cyclonedx"), ("kind", "aibom")],
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        let models = sbom_ai::Entity::find().all(&ctx.db).await?;
        assert_eq!(1, models.len());

        let props = &models[0].properties;

        // Structured field: modelParameters.task → primaryPurpose
        assert_eq!(
            props.get("primaryPurpose").and_then(|v| v.as_str()),
            Some("text-generation"),
        );

        // Structured field: modelParameters.approach.type → typeOfModel
        assert_eq!(
            props.get("typeOfModel").and_then(|v| v.as_str()),
            Some("supervised-learning"),
        );

        // Structured field: considerations.technicalLimitations → limitation (joined)
        assert_eq!(
            props.get("limitation").and_then(|v| v.as_str()),
            Some("Limited to English text; Max 2048 tokens"),
        );

        // Structured field: considerations.ethicalConsiderations → safetyRiskAssessment
        let risks = props.get("safetyRiskAssessment").and_then(|v| v.as_array());
        assert!(risks.is_some());
        let risks = risks.unwrap();
        assert_eq!(risks.len(), 2);
        assert_eq!(
            risks[0].get("name").and_then(|v| v.as_str()),
            Some("Bias in training data"),
        );
        assert_eq!(
            risks[0].get("mitigationStrategy").and_then(|v| v.as_str()),
            Some("Regular auditing of model outputs"),
        );
        assert_eq!(
            risks[1].get("name").and_then(|v| v.as_str()),
            Some("Privacy risks from memorization"),
        );
        assert!(risks[1].get("mitigationStrategy").is_none());

        // Structured field: considerations.fairnessAssessments → fairnessAssessments
        let assessments = props.get("fairnessAssessments").and_then(|v| v.as_array());
        assert!(assessments.is_some());
        let assessments = assessments.unwrap();
        assert_eq!(assessments.len(), 1);
        assert_eq!(
            assessments[0].get("groupAtRisk").and_then(|v| v.as_str()),
            Some("Non-English speakers"),
        );
        assert_eq!(
            assessments[0].get("benefits").and_then(|v| v.as_str()),
            Some("Improved accessibility"),
        );
        assert_eq!(
            assessments[0].get("harms").and_then(|v| v.as_str()),
            Some("Lower accuracy for underrepresented languages"),
        );
        assert_eq!(
            assessments[0]
                .get("mitigationStrategy")
                .and_then(|v| v.as_str()),
            Some("Multilingual fine-tuning planned"),
        );

        // Structured field: considerations.performanceTradeoffs → performanceTradeoffs
        assert_eq!(
            props.get("performanceTradeoffs").and_then(|v| v.as_str()),
            Some("Speed vs accuracy on long sequences; Memory usage scales quadratically"),
        );

        // Structured field: considerations.useCases → useCases
        assert_eq!(
            props.get("useCases").and_then(|v| v.as_str()),
            Some("Conversational AI; Document summarization"),
        );

        // Structured field: considerations.users → users
        assert_eq!(
            props.get("users").and_then(|v| v.as_str()),
            Some("Developers; Researchers"),
        );

        // No generic properties in this fixture, so no bomFormat etc.
        assert!(props.get("bomFormat").is_none());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_cryptographic_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();
        let data = document_bytes("cyclonedx/cryptographic/cbom.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        assert_eq!(0, sbom_crypto::Entity::find().all(&ctx.db).await?.len());

        ctx.db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &data,
                        Format::CycloneDX,
                        [("type", "cyclonedx"), ("kind", "cbom")],
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        assert_eq!(1, sbom_crypto::Entity::find().all(&ctx.db).await?.len());

        Ok(())
    }
}
