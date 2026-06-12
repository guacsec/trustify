use crate::graph::sbom::{
    Checksum, ReferenceSource, common::node::NodeCreator, common::reference::ReferenceCreator,
};
use sea_orm::{ConnectionTrait, DbErr, EntityTrait, Set};
use sea_query::OnConflict;
use serde_cyclonedx::cyclonedx::v_1_6::Component;
use serde_json::{Map, Value};
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::sbom_ai;
use uuid::Uuid;

use super::PackageReference;

pub struct ModelCard {
    pub properties: Value,
}

impl From<&Component> for ModelCard {
    fn from(c: &Component) -> Self {
        let properties = match c.model_card.as_ref() {
            Some(card) => {
                let mut map = Map::new();

                if let Some(params) = &card.model_parameters {
                    if let Some(task) = &params.task {
                        map.insert("primaryPurpose".to_string(), Value::String(task.clone()));
                    }
                    if let Some(approach) = &params.approach
                        && let Some(type_val) = &approach.type_
                    {
                        map.insert("typeOfModel".to_string(), Value::String(type_val.clone()));
                    }
                }

                if let Some(considerations) = &card.considerations {
                    if let Some(limitations) = &considerations.technical_limitations
                        && !limitations.is_empty()
                    {
                        map.insert(
                            "limitation".to_string(),
                            Value::String(limitations.join("; ")),
                        );
                    }

                    if let Some(risks) = &considerations.ethical_considerations
                        && !risks.is_empty()
                    {
                        let arr: Vec<Value> = risks
                            .iter()
                            .map(|r| {
                                let mut obj = Map::new();
                                if let Some(name) = &r.name {
                                    obj.insert("name".to_string(), Value::String(name.clone()));
                                }
                                if let Some(ms) = &r.mitigation_strategy {
                                    obj.insert(
                                        "mitigationStrategy".to_string(),
                                        Value::String(ms.clone()),
                                    );
                                }
                                Value::Object(obj)
                            })
                            .collect();
                        map.insert("safetyRiskAssessment".to_string(), Value::Array(arr));
                    }

                    if let Some(assessments) = &considerations.fairness_assessments
                        && !assessments.is_empty()
                    {
                        let arr: Vec<Value> = assessments
                            .iter()
                            .map(|a| {
                                let mut obj = Map::new();
                                if let Some(v) = &a.group_at_risk {
                                    obj.insert("groupAtRisk".to_string(), Value::String(v.clone()));
                                }
                                if let Some(v) = &a.benefits {
                                    obj.insert("benefits".to_string(), Value::String(v.clone()));
                                }
                                if let Some(v) = &a.harms {
                                    obj.insert("harms".to_string(), Value::String(v.clone()));
                                }
                                if let Some(v) = &a.mitigation_strategy {
                                    obj.insert(
                                        "mitigationStrategy".to_string(),
                                        Value::String(v.clone()),
                                    );
                                }
                                Value::Object(obj)
                            })
                            .collect();
                        map.insert("fairnessAssessments".to_string(), Value::Array(arr));
                    }

                    if let Some(tradeoffs) = &considerations.performance_tradeoffs
                        && !tradeoffs.is_empty()
                    {
                        map.insert(
                            "performanceTradeoffs".to_string(),
                            Value::String(tradeoffs.join("; ")),
                        );
                    }

                    if let Some(use_cases) = &considerations.use_cases
                        && !use_cases.is_empty()
                    {
                        map.insert("useCases".to_string(), Value::String(use_cases.join("; ")));
                    }

                    if let Some(users) = &considerations.users
                        && !users.is_empty()
                    {
                        map.insert("users".to_string(), Value::String(users.join("; ")));
                    }
                }

                // Generic properties take precedence over structured fields
                if let Some(props) = &card.properties {
                    for p in props {
                        map.insert(p.name.clone(), p.value.clone().into());
                    }
                }

                if map.is_empty() {
                    Value::Null
                } else {
                    Value::Object(map)
                }
            }
            None => Value::Null,
        };
        ModelCard { properties }
    }
}

pub struct MachineLearningModelCreator {
    sbom_id: Uuid,
    nodes: NodeCreator,
    refs: ReferenceCreator,
    models: Vec<sbom_ai::ActiveModel>,
}

impl MachineLearningModelCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::new(sbom_id),
            refs: ReferenceCreator::new(sbom_id),
            models: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity: usize) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::with_capacity(sbom_id, capacity),
            refs: ReferenceCreator::with_capacity(sbom_id, capacity),
            models: Vec::with_capacity(capacity),
        }
    }

    pub fn add<'a, I, C>(
        &mut self,
        node_id: String,
        name: String,
        refs: impl Iterator<Item = &'a PackageReference>,
        checksums: I,
        model_card: ModelCard,
    ) where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.refs.add(&node_id, refs);
        self.nodes.add(node_id.clone(), name, checksums);
        self.models.push(sbom_ai::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id),
            properties: Set(model_card.properties),
        });
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        self.nodes.create(db).await?;
        self.refs.create(db).await?;

        for batch in &self.models.into_iter().chunked() {
            sbom_ai::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_ai::Column::SbomId, sbom_ai::Column::NodeId])
                        .do_nothing()
                        .to_owned(),
                )
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

impl<'a> ReferenceSource<'a> for MachineLearningModelCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes.references()
    }
}
