use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use axum::{
    extract::{
        rejection::{ExtensionRejection, TypedHeaderRejection},
        FromRequest, RequestParts,
    },
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json, TypedHeader,
};
use casbin::CoreApi;
use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{Authorizations, SecretKey};

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Operation {
    Read,
    Write,
}

pub struct Authorize<const RESOURCE: &'static str, const OP: &'static str>(pub String);

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
impl<B, const RESOURCE: &'static str, const OP: &'static str> FromRequest<B>
    for Authorize<RESOURCE, OP>
where
    B: Send,
{
    type Rejection = AuthorizationRejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req).await?;

        let Extension(secret) = Extension::<SecretKey>::from_request(req).await?;
        let Extension(Authorizations(enforcer)) =
            Extension::<Authorizations>::from_request(req).await?;

        let bearer_token = bearer.token().to_owned();

        let payload: Payload = bearer_token.verify_with_key(&*secret.0).unwrap();

        let issued_at = Duration::from_secs(payload.issued_at);
        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap();

        if now > issued_at + Duration::from_secs(3600 * 24 * 60) {
            return Err(AuthorizationRejection::ExpiredToken);
        }

        let enforcer = enforcer.read().await;
        if !enforcer.enforce((&payload.name, RESOURCE, OP))? {
            return Err(AuthorizationRejection::Forbidden(RESOURCE, OP));
        }

        Ok(Authorize(payload.name))
    }
}

impl IntoResponse for AuthorizationRejection {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            AuthorizationRejection::Extension(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationRejection::Generic(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationRejection::Casbin(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationRejection::Headers(_) => StatusCode::BAD_REQUEST,
            AuthorizationRejection::InvalidToken | AuthorizationRejection::ExpiredToken => {
                StatusCode::UNAUTHORIZED
            }
            AuthorizationRejection::Forbidden(_, _) => StatusCode::FORBIDDEN,
        };

        let body = Json(json!({
            "message": self.to_string(),
        }))
        .into_response();

        (status, body).into_response()
    }
}
