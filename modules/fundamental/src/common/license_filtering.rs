use sea_orm::IntoSimpleExpr;
use sea_query::{Expr, Func, SimpleExpr};
use trustify_entity::{expanded_license, license};

// License field constant used in query filtering
pub const LICENSE: &str = "license";

/// Creates a COALESCE expression that prefers expanded license text over raw license text.
///
/// Returns: `COALESCE(expanded_license.expanded_text, license.text)`
pub fn license_text_coalesce() -> SimpleExpr {
    Func::coalesce([
        Expr::col((
            expanded_license::Entity,
            expanded_license::Column::ExpandedText,
        ))
        .into_simple_expr(),
        Expr::col((license::Entity, license::Column::Text)).into_simple_expr(),
    ])
    .into()
}
