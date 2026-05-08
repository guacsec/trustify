use crate::graph::{Graph, error::Error};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};
use sea_query::{OnConflict, SelectStatement};
use std::{
    collections::BTreeMap,
    fmt::{Debug, Formatter},
};
use tracing::instrument;
use trustify_common::{cpe::Cpe, db::chunk::EntityChunkedIter};
use trustify_entity::cpe;
use uuid::Uuid;

impl Graph {
    pub async fn get_cpe<C: ConnectionTrait>(
        &self,
        cpe: impl Into<Cpe>,
        connection: &C,
    ) -> Result<Option<CpeContext>, Error> {
        let cpe = cpe.into();

        let query = cpe::Entity::find_by_id(cpe.uuid());

        if let Some(found) = query.one(connection).await? {
            Ok(Some((self, found).into()))
        } else {
            Ok(None)
        }
    }

    pub async fn get_cpe_by_query<C: ConnectionTrait>(
        &self,
        query: SelectStatement,
        connection: &C,
    ) -> Result<Vec<CpeContext>, Error> {
        Ok(cpe::Entity::find()
            .filter(cpe::Column::Id.in_subquery(query))
            .all(connection)
            .await?
            .into_iter()
            .map(|cpe22| (self, cpe22).into())
            .collect())
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn ingest_cpe22<C: ConnectionTrait>(
        &self,
        cpe: impl Into<Cpe> + Debug,
        connection: &C,
    ) -> Result<CpeContext, Error> {
        let cpe = cpe.into();

        if let Some(found) = self.get_cpe(cpe.clone(), connection).await? {
            return Ok(found);
        }

        let entity: cpe::ActiveModel = cpe.into();

        Ok((self, entity.insert(connection).await?).into())
    }
}

#[derive(Clone)]
pub struct CpeContext {
    pub system: Graph,
    pub cpe: cpe::Model,
}

impl From<(&Graph, cpe::Model)> for CpeContext {
    fn from((system, cpe22): (&Graph, cpe::Model)) -> Self {
        Self {
            system: system.clone(),
            cpe: cpe22,
        }
    }
}

impl Debug for CpeContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.cpe.fmt(f)
    }
}

#[derive(Default, Debug)]
pub struct CpeCreator {
    /// CPEs to insert.
    ///
    /// Uses a [`BTreeMap`] to ensure order, avoiding deadlocks on the database
    cpes: BTreeMap<Uuid, (Cpe, cpe::ActiveModel)>,
}

impl CpeCreator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, cpe: Cpe) {
        self.cpes.insert(cpe.uuid(), (cpe.clone(), cpe.into()));
    }

    #[instrument(skip(self, db), fields(num=self.cpes.len()), err(level=tracing::Level::INFO))]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        for batch in &self.cpes.into_values().map(|(_, cpe)| cpe).chunked() {
            cpe::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([cpe::Column::Id])
                        .do_nothing()
                        .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        Ok(())
    }

    // find CPEs matching that id
    pub fn find(&self, id: Uuid) -> Option<&Cpe> {
        self.cpes.get(&id).map(|(cpe, _)| cpe)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_cpe(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new();

        let cpe = Cpe::from_str("cpe:/a:redhat:enterprise_linux:9::crb")?;

        let c1 = graph.ingest_cpe22(cpe.clone(), &ctx.db).await?;
        let c2 = graph.ingest_cpe22(cpe, &ctx.db).await?;

        assert_eq!(c1.cpe.id, c2.cpe.id);

        Ok(())
    }
}
