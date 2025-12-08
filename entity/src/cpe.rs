use cpe::{error::CpeError, uri::Uri};
use sea_orm::{Set, entity::prelude::*};
use std::fmt::{Debug, Display, Formatter};
use trustify_common::cpe::{Component, Cpe, CpeType, Language};
use trustify_common::impl_try_into_cpe;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cpe")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub part: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub update: Option<String>,
    pub edition: Option<String>,
    pub language: Option<String>,
}

impl_try_into_cpe!(Model);

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom_package_cpe_ref::Entity",
        from = "Column::Id",
        to = "super::sbom_package_cpe_ref::Column::CpeId"
    )]
    SbomPackage,
    #[sea_orm(
        belongs_to = "super::product::Entity",
        from = "Column::Product",
        to = "super::product::Column::CpeKey"
    )]
    Product,
    #[sea_orm(
        belongs_to = "super::product_status::Entity",
        from = "Column::Id",
        to = "super::product_status::Column::ContextCpeId"
    )]
    ProductStatus,
}

impl Related<super::sbom_package_cpe_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomPackage.def()
    }
}

impl Related<super::product::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Product.def()
    }
}

impl Related<super::product_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProductStatus.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Display for Model {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut cpe = cpe::uri::Uri::new();
        self.part.as_ref().map(|part| cpe.set_part(part));
        self.vendor.as_ref().map(|vendor| cpe.set_vendor(vendor));
        self.product
            .as_ref()
            .map(|product| cpe.set_product(product));
        self.version
            .as_ref()
            .map(|version| cpe.set_version(version));
        self.update.as_ref().map(|update| cpe.set_update(update));
        self.edition
            .as_ref()
            .map(|edition| cpe.set_edition(edition));
        self.language
            .as_ref()
            .map(|language| cpe.set_language(language));

        Display::fmt(&cpe, f)
    }
}

impl ActiveModel {
    pub fn from_cpe(cpe: Cpe) -> Self {
        ActiveModel {
            id: Set(cpe.uuid()),
            part: match cpe.part() {
                CpeType::Empty => Set(None),
                ct => Set(Some(ct.to_string())),
            },
            vendor: match cpe.vendor() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => Set(None),
                Component::Value(inner) => Set(Some(inner)),
            },
            product: match cpe.product() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => Set(None),
                Component::Value(inner) => Set(Some(inner)),
            },
            version: match cpe.version() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => Set(None),
                Component::Value(inner) => Set(Some(inner)),
            },
            update: match cpe.update() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => Set(None),
                Component::Value(inner) => Set(Some(inner)),
            },
            edition: match cpe.edition() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => Set(None),
                Component::Value(inner) => Set(Some(inner)),
            },
            language: match cpe.language() {
                Language::Any => Set(Some("*".to_string())),
                Language::Language(inner) => Set(Some(inner)),
            },
        }
    }
}

impl From<Cpe> for ActiveModel {
    fn from(value: Cpe) -> Self {
        Self::from_cpe(value)
    }
}

/// A serializable (data only, no id) variant of the CPE, as stored in the database.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CpeDto {
    pub part: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub update: Option<String>,
    pub edition: Option<String>,
    pub language: Option<String>,
}

impl From<Model> for CpeDto {
    fn from(value: Model) -> Self {
        // turn into a model and destructure to ensure we don't miss any new fields

        let Model {
            id: _,
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
        } = value;

        Self {
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
        }
    }
}

impl From<Model> for (Uuid, CpeDto) {
    fn from(value: Model) -> (Uuid, CpeDto) {
        // turn into a model and destructure to ensure we don't miss any new fields

        let Model {
            id,
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
        } = value;

        (
            id,
            CpeDto {
                part,
                vendor,
                product,
                version,
                update,
                edition,
                language,
            },
        )
    }
}

macro_rules! apply {
    ($c: expr, $v:expr => $n:ident) => {
        if let Some($n) = &$v.$n {
            $c.$n($n);
        }
    };
    ($c: expr, $v:expr => $n:ident, $($m:ident),+) => {
        apply!($c, $v => $n );
        apply!($c, $v => $($m),+)
    };
}

macro_rules! apply_fix {
    ($c: expr, $v:expr => $n:ident) => {
        if let Some($n) = &$v.$n {
            if $n == "*" {
                $c.$n("");
            } else {
                $c.$n($n);
            }

        }
    };
    ($c: expr, $v:expr => $n:ident, $($m:tt),+) => {
        apply_fix!($c, $v => $n );
        apply_fix!($c, $v => $($m),+)
    };
}

/// Convert from the DTO into an actual one
impl TryFrom<CpeDto> for Cpe {
    type Error = CpeError;

    fn try_from(value: CpeDto) -> Result<Self, Self::Error> {
        let mut cpe = Uri::builder();

        apply!(cpe, value => part);
        apply_fix!(cpe, value => vendor, product, version, update, edition);

        // apply the fix for the language field

        if let Some(language) = &value.language {
            if language == "*" {
                cpe.language("ANY");
            } else {
                cpe.language(language);
            }
        }

        cpe.validate().map(|cpe| cpe.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sea_orm::TryIntoModel;
    use std::str::FromStr;

    use test_log::test;
    use trustify_common::cpe::Cpe;

    // currently broken due to: https://github.com/KenDJohnson/cpe-rs/issues/9
    #[test]
    fn test_roundtrip() {
        // from here we start
        const CPE: &str = "cpe:/a:redhat:openshift_container_storage:4.8::el8";

        // parse into a CPE
        let cpe = Cpe::from_str(CPE).unwrap();

        let id = cpe.uuid();

        // turn it into a model to be inserted
        let model = ActiveModel {
            id: Set(id),
            ..cpe.into()
        };

        assert_eq!(model.part, Set(Some("a".to_string())));
        assert_eq!(model.vendor, Set(Some("redhat".to_string())));
        assert_eq!(
            model.product,
            Set(Some("openshift_container_storage".to_string()))
        );
        assert_eq!(model.version, Set(Some("4.8".to_string())));
        assert_eq!(model.update, Set(Some("*".to_string())));
        assert_eq!(model.edition, Set(Some("el8".to_string())));
        assert_eq!(model.language, Set(Some("*".to_string())));

        log::info!("cpe: {model:#?}");

        let (id, dto): (Uuid, CpeDto) = model.try_into_model().unwrap().into();

        // and turn it back into a CPE

        let cpe: Cpe = dto.try_into().expect("must be able to build cpe");

        // ensure it's the same as the original one

        assert_eq!(CPE, format!("{cpe:0}"));

        // including the v5 UUID

        assert_eq!(id, cpe.uuid());
    }
}
