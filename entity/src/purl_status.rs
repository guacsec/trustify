use sea_orm::{
    LinkDef, QueryTrait, Select,
    entity::prelude::*,
    sea_query::{Alias, ExprTrait, IntoCondition, IntoIden, TableName, TableRef},
};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "purl_status")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status_id: Uuid,
    pub base_purl_id: Uuid,
    pub version_range_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
    /// The product the assertion is stated in, if any.
    pub assertion_context_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::version_range::Entity"
        from = "Column::VersionRangeId",
        to = "super::version_range::Column::Id"
    )]
    VersionRange,

    #[sea_orm(belongs_to = "super::base_purl::Entity",
        from = "Column::BasePurlId"
        to = "super::base_purl::Column::Id"
    )]
    BasePurl,

    #[sea_orm(has_many = "super::versioned_purl::Entity")]
    VersionedPurl,

    #[sea_orm(belongs_to = "super::vulnerability::Entity",
        from = "Column::VulnerabilityId"
        to = "super::vulnerability::Column::Id"
    )]
    Vulnerability,

    #[sea_orm(belongs_to = "super::advisory::Entity",
        from = "Column::AdvisoryId"
        to = "super::advisory::Column::Id"
    )]
    Advisory,

    #[sea_orm(belongs_to = "super::status::Entity",
        from = "Column::StatusId"
        to = "super::status::Column::Id"
    )]
    Status,

    #[sea_orm(belongs_to = "super::advisory_vulnerability::Entity",
        from = "(Column::AdvisoryId, Column::VulnerabilityId)"
        to = "(super::advisory_vulnerability::Column::AdvisoryId, super::advisory_vulnerability::Column::VulnerabilityId)"
    )]
    AdvisoryVulnerability,

    #[sea_orm(belongs_to = "super::cpe::Entity",
        from = "Column::ContextCpeId"
        to = "super::cpe::Column::Id"
    )]
    ContextCpe,
}

pub struct VersionedPurlLink;

impl Linked for VersionedPurlLink {
    type FromEntity = Entity;
    type ToEntity = super::versioned_purl::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![
            Relation::VersionRange.def(),
            super::version_range::Relation::VersionedPurls.def(),
        ]
    }
}

impl Related<super::version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionRange.def()
    }
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::BasePurl.def()
    }
}

impl Related<super::versioned_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionedPurl.def()
    }
}

impl Related<super::vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }
}

impl Related<super::advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl Related<super::status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Status.def()
    }
}

impl Related<super::advisory_vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdvisoryVulnerability.def()
    }
}

impl Related<super::cpe::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ContextCpe.def()
    }
}

impl Related<super::remediation::Entity> for Entity {
    fn to() -> RelationDef {
        super::remediation_purl_status::Relation::Remediation.def()
    }

    fn via() -> Option<RelationDef> {
        Some(
            super::remediation_purl_status::Relation::PurlStatus
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// The view of the stated statuses plus the ones implied by correlation options (e.g. "affected"
/// below a Red Hat `fixed`), as a bridge for the fundamental APIs. Its rows carry a `derived`
/// flag, matching the one of [`super::version_range::EFFECTIVE_VIEW`].
pub const EFFECTIVE_VIEW: &str = "purl_status_effective";

/// Find the rows of [`EFFECTIVE_VIEW`], under the name of this table, so that its columns and
/// relations apply.
pub fn find_effective() -> Select<Entity> {
    let mut select = Entity::find();
    QueryTrait::query(&mut select)
        .from_clear()
        .from_as(Alias::new(EFFECTIVE_VIEW), Entity);
    select
}

/// Read the `purl_status` side of a relation to it (e.g. from `base_purl`) from
/// [`EFFECTIVE_VIEW`].
pub fn effective(mut rel: RelationDef) -> RelationDef {
    rel.to_tbl = read_from_view(rel.to_tbl, EFFECTIVE_VIEW);
    rel
}

/// The relation to the version range, read from [`super::version_range::EFFECTIVE_VIEW`], for
/// rows of [`EFFECTIVE_VIEW`]: a derived status has the derived range of the same ID.
pub fn effective_version_range() -> RelationDef {
    let mut rel = Relation::VersionRange.def();
    rel.to_tbl = read_from_view(rel.to_tbl, super::version_range::EFFECTIVE_VIEW);
    rel.on_condition(|from, to| {
        Expr::col((from, Alias::new("derived")))
            .equals((to, Alias::new("derived")))
            .into_condition()
    })
}

/// Read a table from a view, aliased as the table.
fn read_from_view(table: TableRef, view: &'static str) -> TableRef {
    match table {
        TableRef::Table(TableName(schema, name), alias) => TableRef::Table(
            TableName(schema, Alias::new(view).into_iden()),
            Some(alias.unwrap_or(name)),
        ),
        other => other,
    }
}
