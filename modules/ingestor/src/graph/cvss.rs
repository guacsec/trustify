use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set};
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::advisory_vulnerability_score;
use uuid::Uuid;

#[derive(Debug)]
pub struct ScoreCreator {
    advisory_id: Uuid,
    scores: Vec<advisory_vulnerability_score::ActiveModel>,
}

impl ScoreCreator {
    pub fn new(advisory_id: Uuid) -> Self {
        Self {
            advisory_id,
            scores: Vec::new(),
        }
    }

    pub fn add(&mut self, model: impl Into<advisory_vulnerability_score::ActiveModel>) {
        self.scores.push(model.into());
    }

    pub fn extend(
        &mut self,
        items: impl IntoIterator<Item = advisory_vulnerability_score::ActiveModel>,
    ) {
        self.scores.extend(items)
    }

    pub async fn create(mut self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        // delete existing entries

        advisory_vulnerability_score::Entity::delete_many()
            .filter(advisory_vulnerability_score::Column::AdvisoryId.eq(self.advisory_id))
            .exec(db)
            .await?;

        // set advisory

        for score in &mut self.scores {
            score.advisory_id = Set(self.advisory_id);
        }

        // insert chunked

        for batch in &self.scores.chunked() {
            advisory_vulnerability_score::Entity::insert_many(batch)
                .exec(db)
                .await?;
        }

        // done

        Ok(())
    }
}
