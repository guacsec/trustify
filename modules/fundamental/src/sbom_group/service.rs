use sea_query::ExprTrait;
use std::borrow::Cow;

pub struct SbomGroupService {
    max_group_name_length: usize,
}

impl SbomGroupService {
    pub fn new(max_group_name_length: usize) -> Self {
        Self {
            max_group_name_length,
        }
    }

    /// Ensure a group name is valid
    ///
    /// This does not check uniqueness in the context of the parent.
    fn validate_group_name(&self, name: &str) -> Vec<Cow<'static, str>> {
        let mut result = vec![];

        if name.is_empty() {
            result.push("name must not be empty".into());
        }

        if name.len() > self.max_group_name_length {
            result.push(
                format!(
                    "name must be less than {} characters",
                    self.max_group_name_length
                )
                .into(),
            );
        }

        if name.star

        result
    }
}
