use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use trustify_entity::labels::Labels;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
pub struct Group {
    /// The ID of the group
    pub id: String,

    /// The parent of this group
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,

    /// The name of the group, in the context of its parent
    pub name: String,

    /// Additional group labels
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,

    pub name: String,

    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
}
