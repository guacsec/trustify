use crate::{
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Requirement, RequirementError},
};
use strum::ParseError;

macro_rules! permission {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident
            ),* $(,)?
        }
    ) => {
        // Define the enum itself
        $(#[$enum_meta])*
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
        }

        $(
            pub struct $variant;

            impl Requirement for $variant {
                fn enforce(authorizer: &Authorizer, user: &UserInformation) -> Result<(), RequirementError> {
                    Ok(authorizer.require(user, Permission::$variant)?)
                }
            }

        )*
    };
}

permission! {
    #[derive(
        Copy,
        Clone,
        PartialEq,
        Eq,
        Debug,
        serde::Deserialize,
        serde::Serialize,
        Hash,
        schemars::JsonSchema,
        strum::AsRefStr,
        strum::Display,
        strum::EnumString,
        strum::IntoStaticStr,
    )]
    #[serde(into = "String")]
    #[serde(try_from = "String")]
    pub enum Permission {
        #[strum(serialize = "create.sbom")]
        CreateSbom,
        #[strum(serialize = "read.sbom")]
        ReadSbom,
        #[strum(serialize = "update.sbom")]
        UpdateSbom,
        #[strum(serialize = "delete.sbom")]
        DeleteSbom,

        #[strum(serialize = "create.advisory")]
        CreateAdvisory,
        #[strum(serialize = "read.advisory")]
        ReadAdvisory,
        #[strum(serialize = "update.advisory")]
        UpdateAdvisory,
        #[strum(serialize = "delete.advisory")]
        DeleteAdvisory,

        #[strum(serialize = "create.importer")]
        CreateImporter,
        #[strum(serialize = "read.importer")]
        ReadImporter,
        #[strum(serialize = "update.importer")]
        UpdateImporter,
        #[strum(serialize = "delete.importer")]
        DeleteImporter,

        #[strum(serialize = "create.weakness")]
        CreateWeakness,
        #[strum(serialize = "read.weakness")]
        ReadWeakness,
        #[strum(serialize = "update.weakness")]
        UpdateWeakness,
        #[strum(serialize = "delete.weakness")]
        DeleteWeakness,

        #[strum(serialize = "create.metadata")]
        CreateMetadata,
        #[strum(serialize = "read.metadata")]
        ReadMetadata,
        #[strum(serialize = "update.metadata")]
        UpdateMetadata,
        #[strum(serialize = "delete.metadata")]
        DeleteMetadata,

        #[strum(serialize = "create.sbomGroup")]
        CreateSbomGroup,
        #[strum(serialize = "read.sbomGroup")]
        ReadSbomGroup,
        #[strum(serialize = "update.sbomGroup")]
        UpdateSbomGroup,
        #[strum(serialize = "delete.sbomGroup")]
        DeleteSbomGroup,

        #[strum(serialize = "upload.dataset")]
        UploadDataset,

        #[strum(serialize = "read.systemInformation")]
        ReadSystemInformation,

        #[strum(serialize = "ai")]
        Ai,
    }
}

impl TryFrom<String> for Permission {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl From<Permission> for String {
    fn from(value: Permission) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serde() {
        assert_eq!(
            json!("read.advisory"),
            serde_json::to_value(Permission::ReadAdvisory).unwrap(),
        );
        assert_eq!(
            Permission::ReadAdvisory,
            serde_json::from_value(json!("read.advisory")).unwrap(),
        );
    }
}
