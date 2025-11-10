use sea_orm::{ConnectionTrait, DbErr};
use sea_orm_migration::SchemaManager;
use sea_query::{IntoIden, extension::postgres::Type};

/// create a type, if it not already exists
///
/// This is required as Postgres doesn't support `CREATE TYPE IF NOT EXISTS`
pub async fn create_enum_if_not_exists<T, I>(
    manager: &SchemaManager<'_>,
    name: impl IntoIden + Clone,
    values: I,
) -> Result<(), DbErr>
where
    T: IntoIden,
    I: IntoIterator<Item = T>,
{
    let builder = manager.get_connection().get_database_backend();
    let r#type = name.clone().into_iden();
    let stmt = builder.build(Type::create().as_enum(name).values(values));
    let stmt = format!(
        r#"
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = '{name}'
  ) THEN
    {stmt};
  END IF;
END$$;
"#,
        name = r#type.to_string()
    );

    manager.get_connection().execute_unprepared(&stmt).await?;

    Ok(())
}
