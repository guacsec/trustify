use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use trustify_entity::{labels::Labels, sbom_group};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
pub struct Group {
    /// The ID of the group
    pub id: String,

    /// The direct parent of this group
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,

    /// The name of the group, in the context of its parent
    pub name: String,

    /// A user friendly description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Additional group labels
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
}

impl From<sbom_group::Model> for Group {
    fn from(value: sbom_group::Model) -> Self {
        Self {
            id: value.id.to_string(),
            parent: value.parent.map(|id| id.to_string()),
            name: value.name,
            description: value.description,
            labels: value.labels,
        }
    }
}

/// Detailed group information, extends [`Group`]
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
pub struct GroupDetails {
    #[serde(flatten)]
    pub group: Group,

    /// The number of groups owned directly by this group
    ///
    /// This information is only present when requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_of_groups: Option<u64>,
    /// The number of SBOMs directly assigned to this group
    ///
    /// This information is only present when requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_of_sboms: Option<u64>,
    /// The path, of IDs, from the root to this group
    ///
    /// This information is only present when requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parents: Option<Vec<String>>,
}

impl Deref for GroupDetails {
    type Target = Group;

    fn deref(&self) -> &Self::Target {
        &self.group
    }
}

impl DerefMut for GroupDetails {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.group
    }
}

/// Mutable properties of a [`Group`].
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
pub struct GroupRequest {
    /// The name of the group.
    pub name: String,

    /// The ID of the group's parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,

    /// A user provided description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
}
