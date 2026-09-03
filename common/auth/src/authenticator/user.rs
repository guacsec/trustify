//! Structures to work with users and identities.

use crate::authenticator::error::{AuthenticationError, AuthorizationError};

/// Details of an authenticated user.
///
/// **NOTE:** When you don't require the user to be authenticated, it is possible to use
/// the extraction for [`UserInformation`].
///
/// ## Extraction
///
/// This value can be extracted by `actix` like this:
///
/// ```rust
/// # use actix_web::post;
/// # use actix_web::Responder;
/// use trustify_auth::authenticator::user::UserDetails;
///
/// #[post("/api")]
/// async fn perform_operation(
///     user: UserDetails,
/// ) -> impl Responder {
///   // [...]
///   "Hello World"
/// }
/// ```
///
/// Extraction, and the request, will fail with `401` when the user is not authenticated,
/// and `403` when the user is [`UserInformation::Anonymous`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDetails {
    pub id: String,
    pub permissions: Vec<String>,
}

impl UserDetails {
    pub fn require_permission(
        &self,
        permission: impl AsRef<str>,
    ) -> Result<(), AuthorizationError> {
        let permission = permission.as_ref();
        log::debug!("Requiring scope: {permission}");

        if self.permissions.iter().any(|r| r == permission) {
            Ok(())
        } else {
            Err(AuthorizationError::Failed)
        }
    }
}

/// Information about the authenticated user, may be anonymous
///
/// ## Extraction
///
/// This value can be extracted from an `actix` request.
#[derive(Clone, Debug)]
pub enum UserInformation {
    Authenticated(UserDetails),
    Anonymous,
}

#[allow(unused)]
impl UserInformation {
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Authenticated(details) => Some(&details.id),
            Self::Anonymous => None,
        }
    }
}

/// Extractor for user information.
#[cfg(feature = "actix")]
impl actix_web::FromRequest for UserInformation {
    type Error = actix_web::Error;
    type Future = core::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        use actix_web::HttpMessage;
        match req.extensions().get::<UserInformation>() {
            Some(user) => core::future::ready(Ok(user.clone())),
            None => core::future::ready(Ok(UserInformation::Anonymous)),
        }
    }
}

/// Extractor for user details, requires an authenticated user.
#[cfg(feature = "actix")]
impl actix_web::FromRequest for UserDetails {
    type Error = actix_web::Error;
    type Future = core::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        use actix_web::HttpMessage;
        match req.extensions().get::<UserInformation>() {
            Some(UserInformation::Authenticated(details)) => {
                core::future::ready(Ok(details.clone()))
            }
            Some(UserInformation::Anonymous) => {
                log::debug!("Anonymous user, returning failure");
                core::future::ready(Err(AuthorizationError::Failed.into()))
            }
            None => core::future::ready(Err(AuthenticationError::Failed.into())),
        }
    }
}
