use actix_web::http::header::IfMatch;

/// Extract the revision from an [`IfMatch`].
pub fn extract_revision(if_match: &IfMatch) -> Option<&str> {
    match if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    }
}
