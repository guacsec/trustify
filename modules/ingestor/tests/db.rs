#![recursion_limit = "256"]
use hex::ToHex;
use sea_orm::{ConnectionTrait, EntityTrait, QueryOrder};
use std::fmt::Display;
use test_context::test_context;
use test_log::test;
use time::{Duration, macros::datetime};
use trustify_common::hashing::Digests;
use trustify_entity::{advisory, source_document};
use trustify_module_ingestor::graph::advisory::AdvisoryInformation;
use trustify_test_context::TrustifyContext;

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    pub identifier: String,
    pub sha256: String,
    pub deprecated: bool,
}

impl Entry {
    pub fn new(
        identifier: impl Into<String>,
        id: impl Display,
        deprecated: bool,
    ) -> anyhow::Result<Self> {
        let identifier = identifier.into();
        let id = format!("{identifier}/{id}");
        let digests = Digests::digest(&id);

        Ok(Self {
            identifier,
            sha256: digests.sha256.encode_hex(),
            deprecated,
        })
    }
}

/// Ensure that updating all at once groups by document identifier.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn update_deprecated_all(ctx: &TrustifyContext) -> anyhow::Result<()> {
    create_set(ctx).await?;
    reset_all(ctx).await?;

    // next, run the function to update them all

    ctx.db
        .execute_unprepared("SELECT update_deprecated_advisory()")
        .await?;

    // check

    let all = get_all(ctx).await?;

    assert_eq!(
        all,
        vec![
            Entry::new("A", "1", true)?,
            Entry::new("A", "2", true)?,
            Entry::new("A", "3", true)?,
            Entry::new("A", "4", false)?,
            Entry::new("B", "1", true)?,
            Entry::new("B", "2", true)?,
            Entry::new("B", "3", true)?,
            Entry::new("B", "4", false)?,
            Entry::new("C", "1", true)?,
            Entry::new("C", "2", true)?,
            Entry::new("C", "3", true)?,
            Entry::new("C", "4", false)?,
            Entry::new("D", "1", true)?,
            Entry::new("D", "2", true)?,
            Entry::new("D", "3", true)?,
            Entry::new("D", "4", false)?,
        ]
    );

    // done

    Ok(())
}

/// Ensure that updating only one, actually does update only one, grouped by identifier.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn update_deprecated_one(ctx: &TrustifyContext) -> anyhow::Result<()> {
    create_set(ctx).await?;
    reset_all(ctx).await?;

    // next, run the function to update only one

    ctx.db
        .execute_unprepared("SELECT update_deprecated_advisory('B')")
        .await?;

    let all = get_all(ctx).await?;

    assert_eq!(
        all,
        vec![
            Entry::new("A", "1", false)?,
            Entry::new("A", "2", false)?,
            Entry::new("A", "3", false)?,
            Entry::new("A", "4", false)?,
            Entry::new("B", "1", true)?,
            Entry::new("B", "2", true)?,
            Entry::new("B", "3", true)?,
            Entry::new("B", "4", false)?,
            Entry::new("C", "1", false)?,
            Entry::new("C", "2", false)?,
            Entry::new("C", "3", false)?,
            Entry::new("C", "4", false)?,
            Entry::new("D", "1", false)?,
            Entry::new("D", "2", false)?,
            Entry::new("D", "3", false)?,
            Entry::new("D", "4", false)?,
        ]
    );

    // done

    Ok(())
}

async fn create_set(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let graph = &ctx.graph;

    let published = datetime!(2024-01-01 00:00 UTC);

    for d in ["A", "B", "C", "D"] {
        for i in [1, 2, 3, 4] {
            let id = format!("{d}/{i}");
            let digests = Digests::digest(&id);
            let modified = published + Duration::days(i as i64);

            let info = AdvisoryInformation {
                id,
                title: None,
                issuer: None,
                published: Some(published),
                modified: Some(modified),
                withdrawn: None,
                version: None,
            };
            graph
                .ingest_advisory(d, (), &digests, info, &ctx.db)
                .await?;
        }
    }

    Ok(())
}

async fn reset_all(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // now mark them all as non-deprecated

    ctx.db
        .execute_unprepared("UPDATE advisory SET deprecated = false")
        .await?;

    Ok(())
}

async fn get_all(ctx: &TrustifyContext) -> anyhow::Result<Vec<Entry>> {
    let all = advisory::Entity::find()
        .find_also_related(source_document::Entity)
        .order_by_asc(advisory::Column::Identifier)
        .order_by_asc(advisory::Column::Modified)
        .all(&ctx.db)
        .await?;

    Ok(all
        .into_iter()
        .filter_map(|(adv, doc)| {
            Some(Entry {
                identifier: adv.identifier,
                sha256: doc?.sha256,
                deprecated: adv.deprecated,
            })
        })
        .collect::<Vec<_>>())
}
