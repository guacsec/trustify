use crate::version_scheme::VersionScheme;
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{Asterisk, Func, IntoCondition, SimpleExpr};
use trustify_common::db::VersionMatches;

/// The view of the stated ranges plus, for each exact version, the range below it (as a range of
/// the same ID, flagged `derived`), for the statuses of [`super::purl_status::EFFECTIVE_VIEW`].
pub const EFFECTIVE_VIEW: &str = "version_range_effective";

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "version_range")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    // The ID of the version scheme, which is a human-friend string key like `semver`.
    pub version_scheme_id: VersionScheme,
    pub low_version: Option<String>,
    pub low_inclusive: Option<bool>,
    pub high_version: Option<String>,
    pub high_inclusive: Option<bool>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    PackageStatus,
    VersionedPurls,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Relation::PackageStatus => Entity::belongs_to(super::purl_status::Entity)
                .from(Column::Id)
                .to(super::purl_status::Column::VersionRangeId)
                .into(),
            Relation::VersionedPurls => Entity::has_many(super::versioned_purl::Entity)
                .on_condition(|_left, _right| {
                    SimpleExpr::FunctionCall(
                        Func::cust(VersionMatches)
                            .arg(Expr::col((
                                super::versioned_purl::Entity,
                                super::versioned_purl::Column::Version,
                            )))
                            .arg(Expr::col((Entity, Asterisk))),
                    )
                    .into_condition()
                })
                .into(),
        }
    }
}

impl Related<super::purl_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageStatus.def()
    }
}

impl Related<super::versioned_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageStatus.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
