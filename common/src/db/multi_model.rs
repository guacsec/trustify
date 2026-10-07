use sea_orm::{
    ColumnTrait, DbErr, EntityTrait, FromQueryResult, IntoIdentity, IntoSimpleExpr, Iterable,
    QueryResult, QuerySelect, Select, SelectModel, Selector,
};
use sea_query::{ColumnName, ColumnRef, Expr, SimpleExpr};

pub trait ColumnsPrefixed: Sized {
    fn try_columns_prefixed<C, I>(self, prefix: &str, cols: I) -> Result<Self, DbErr>
    where
        C: ColumnTrait,
        I: IntoIterator<Item = C>;
}

impl<T: QuerySelect> ColumnsPrefixed for T {
    fn try_columns_prefixed<C, I>(mut self, prefix: &str, cols: I) -> Result<Self, DbErr>
    where
        C: ColumnTrait,
        I: IntoIterator<Item = C>,
    {
        for col in cols.into_iter() {
            if let SimpleExpr::Column(col_ref) = col.into_simple_expr() {
                match col_ref {
                    ColumnRef::Column(ColumnName(_, ref name)) => {
                        let prefixed = format!("{prefix}{name}");
                        self = self.column_as(col, prefixed);
                    }
                    ColumnRef::Asterisk(_) => {
                        return Err(DbErr::Custom("Unable to prefix asterisk".to_string()));
                    }
                    _ => {
                        return Err(DbErr::Custom("Unable to prefix column".to_string()));
                    }
                }
            } else {
                return Err(DbErr::Custom("Unable to prefix column".to_string()));
            }
        }
        Ok(self)
    }
}

pub trait SelectIntoMultiModel: Sized {
    fn try_model_columns<E: EntityTrait>(self, entity: E) -> Result<Self, DbErr>;

    fn try_model_columns_from_alias<E: EntityTrait>(
        self,
        entity: E,
        table_alias: &str,
    ) -> Result<Self, DbErr>;

    fn try_into_multi_model<M>(self) -> Result<Selector<SelectModel<M>>, DbErr>
    where
        M: FromQueryResultMultiModel;
}

impl<E: EntityTrait> SelectIntoMultiModel for Select<E> {
    fn try_model_columns<O: EntityTrait>(self, entity: O) -> Result<Self, DbErr> {
        let name = entity.table_name();
        let prefix = format!("{name}$");
        self.try_columns_prefixed(&prefix, O::Column::iter())
    }

    fn try_model_columns_from_alias<O: EntityTrait>(
        mut self,
        _entity: O,
        table_alias: &str,
    ) -> Result<Self, DbErr> {
        let prefix = format!("{table_alias}$");
        for simple_col in O::Column::iter() {
            if let SimpleExpr::Column(col_ref) = simple_col.into_simple_expr() {
                match col_ref {
                    ColumnRef::Column(ColumnName(_, name)) => {
                        let prefixed = format!("{prefix}{name}");
                        self = self
                            .column_as(Expr::col((table_alias.into_identity(), name)), prefixed);
                    }
                    ColumnRef::Asterisk(_) => {
                        return Err(DbErr::Custom("Unable to prefix asterisk".to_string()));
                    }
                    _ => {
                        return Err(DbErr::Custom("Unable to prefix column".to_string()));
                    }
                }
            } else {
                return Err(DbErr::Custom("Unable to prefix column".to_string()));
            }
        }

        Ok(self)
    }

    fn try_into_multi_model<M>(self) -> Result<Selector<SelectModel<M>>, DbErr>
    where
        M: FromQueryResultMultiModel,
    {
        let select = M::try_into_multi_model(self)?;
        Ok(select.into_model::<M>())
    }
}

pub trait FromQueryResultMultiModel: FromQueryResult {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr>;

    fn from_query_result_multi_model<E: EntityTrait>(
        res: &QueryResult,
        alias: &str,
        entity: E,
    ) -> Result<E::Model, DbErr> {
        let prefix = if alias.is_empty() {
            let name = entity.table_name();
            format!("{name}$")
        } else {
            format!("{alias}$")
        };

        E::Model::from_query_result(res, &prefix)
    }

    fn from_query_result_multi_model_optional<E: EntityTrait>(
        res: &QueryResult,
        alias: &str,
        entity: E,
    ) -> Result<Option<E::Model>, DbErr> {
        Ok(Self::from_query_result_multi_model(res, alias, entity).ok())
    }
}
