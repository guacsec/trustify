use std::marker::PhantomData;
use utoipa::{
    IntoParams,
    openapi::{
        ObjectBuilder, Type,
        path::{Parameter, ParameterBuilder, ParameterIn},
    },
};

pub trait Query {
    fn generate_query_description() -> String;
    fn generate_sort_description() -> String;
}

pub struct TrustifyQuery<T: Query> {
    phantom: PhantomData<T>,
}

impl<T: Query> IntoParams for TrustifyQuery<T> {
    fn into_params(_parameter_in_provider: impl Fn() -> Option<ParameterIn>) -> Vec<Parameter> {
        vec![
            ParameterBuilder::new()
                .name("q")
                .parameter_in(ParameterIn::Query)
                .description(Some(T::generate_query_description()))
                .schema(Some(ObjectBuilder::new().schema_type(Type::String)))
                .build(),
            ParameterBuilder::new()
                .name("sort")
                .parameter_in(ParameterIn::Query)
                .description(Some(T::generate_sort_description()))
                .schema(Some(ObjectBuilder::new().schema_type(Type::String)))
                .build(),
        ]
    }
}
