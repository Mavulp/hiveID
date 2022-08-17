use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use axum::{
    body::{boxed, Empty},
    extract::{
        rejection::{ExtensionRejection, TypedHeaderRejection},
        FromRequest, RequestParts,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use casbin::CoreApi;
use jwt::VerifyWithKey;
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{Authorizations, Cookies, SecretKey, Variables};

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Operation {
    Read,
    Write,
}

pub struct Authorize<
    const RESOURCE: &'static str = "",
    const OP: &'static str = "",
    const API: bool = false,
>(pub String);

pub type ApiAuthorize<const RESOURCE: &'static str = "", const OP: &'static str = ""> =
    Authorize<RESOURCE, OP, true>;

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub name: String,
    pub issued_at: u64,
}

#[derive(Debug, Error)]
pub enum AuthorizationRejection {
    #[error("{0}")]
    Extension(#[from] ExtensionRejection),
    #[error("{0}")]
    Headers(#[from] TypedHeaderRejection),
    #[error("Missing auth header")]
    MissingAuth(String),
    #[error("Missing auth header")]
    MissingApiAuth,
    #[error("Invalid session, please login again")]
    InvalidToken,
    #[error("Your session has expired, please login again")]
    ExpiredToken,
    #[error("Not allowed to perform {1:?} on {0:?}")]
    Forbidden(&'static str, &'static str),
    #[error("{0}")]
    Casbin(#[from] casbin::Error),
    #[error("{0}")]
    Generic(#[from] anyhow::Error),
}

#[async_trait]
impl<B, const RESOURCE: &'static str, const OP: &'static str, const API: bool> FromRequest<B>
    for Authorize<RESOURCE, OP, API>
where
    B: Send,
{
    type Rejection = AuthorizationRejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Cookies(jar) = Cookies::from_request(req).await.unwrap();

        let token = match jar.get("__auth") {
            Some(token) => token,
            None => {
                if API {
                    return Err(AuthorizationRejection::MissingApiAuth);
                } else {
                    // redirect to IDP login site when not in an API call (eg. rendering html
                    // templates)
                    debug!("Failed to find auth cookie. Redirecting to IDP");

                    let Extension(variables) =
                        Extension::<Arc<Variables>>::from_request(req).await?;

                    let redirect = format!(
                        "{}?service={}&redirect_to={}",
                        variables.idp_login_address,
                        variables.service_name,
                        urlencoding::encode(req.uri().path())
                    );

                    return Err(AuthorizationRejection::MissingAuth(redirect));
                }
            }
        };

        let Extension(secret) = Extension::<SecretKey>::from_request(req).await?;
        let Extension(Authorizations(enforcer)) =
            Extension::<Authorizations>::from_request(req).await?;

        let payload: Payload = token.value().verify_with_key(&*secret.0).unwrap();

        let issued_at = Duration::from_secs(payload.issued_at);
        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap();

        // tokens are only valid for 60 days
        if now > issued_at + Duration::from_secs(3600 * 24 * 60) {
            return Err(AuthorizationRejection::ExpiredToken);
        }

        if !RESOURCE.is_empty() && !OP.is_empty() {
            let enforcer = enforcer.read().await;
            if !enforcer.enforce((&payload.name, RESOURCE, OP))? {
                return Err(AuthorizationRejection::Forbidden(RESOURCE, OP));
            }
        }

        Ok(Authorize(payload.name))
    }
}

impl IntoResponse for AuthorizationRejection {
    fn into_response(self) -> axum::response::Response {
        // redirect to IDP login when auth headers are missing
        if let AuthorizationRejection::MissingAuth(redirect) = &self {
            let response = Response::builder()
                .header("Location", redirect)
                .status(StatusCode::SEE_OTHER)
                .body(boxed(Empty::new()))
                .unwrap();

            return response;
        }

        let status = match &self {
            AuthorizationRejection::Extension(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationRejection::Generic(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationRejection::Casbin(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationRejection::Headers(_) => StatusCode::BAD_REQUEST,
            AuthorizationRejection::InvalidToken | AuthorizationRejection::ExpiredToken => {
                StatusCode::UNAUTHORIZED
            }
            AuthorizationRejection::Forbidden(_, _) => StatusCode::FORBIDDEN,
            AuthorizationRejection::MissingApiAuth | AuthorizationRejection::MissingAuth(_) => {
                StatusCode::UNAUTHORIZED
            }
        };

        let body = Json(json!({
            "message": self.to_string(),
        }))
        .into_response();

        (status, body).into_response()
    }
}
