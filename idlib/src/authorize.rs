use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::Context;
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
use jwt::VerifyWithKey;
use log::{debug};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{Cookies, SecretKey, Variables};

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Operation {
    Read,
    Write,
}

pub struct AuthorizeCookie<const GROUP: Option<&'static str> = None>(pub Payload);

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub name: String,
    pub issued_at: u64,
    pub groups: Vec<String>,
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
    #[error("User is not part of group {0:?}")]
    Forbidden(&'static str),
    #[error("{0}")]
    Generic(#[from] anyhow::Error),
}

#[async_trait]
impl<B, const GROUP: Option<&'static str>> FromRequest<B> for AuthorizeCookie<GROUP>
where
    B: Send,
{
    type Rejection = AuthorizationRejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Cookies(jar) = Cookies::from_request(req).await.unwrap();

        let token = match jar.get("__auth") {
            Some(token) => token,
            None => {
                debug!("Failed to find auth cookie. Redirecting to IDP");

                let Extension(variables) = Extension::<Arc<Variables>>::from_request(req).await?;

                // TODO: use client ID instead of service name
                let redirect = format!(
                    "{}?service={}&redirect_to={}",
                    variables.idp_login_address,
                    variables.service_name,
                    urlencoding::encode(req.uri().path())
                );

                return Err(AuthorizationRejection::MissingAuth(redirect));
            }
        };

        let Extension(secret) = Extension::<SecretKey>::from_request(req).await?;
        let payload: Payload = token.value().verify_with_key(&*secret.0).context("Failed to parse JWT")?;

        let issued_at = Duration::from_secs(payload.issued_at);
        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap();

        // tokens are only valid for 60 days
        if now > issued_at + Duration::from_secs(3600 * 24 * 60) {
            return Err(AuthorizationRejection::ExpiredToken);
        }

        if let Some(group) = GROUP {
            if !payload.groups.iter().any(|s| s == group) {
                return Err(AuthorizationRejection::Forbidden(group));
            }
        }

        Ok(AuthorizeCookie(payload))
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
            AuthorizationRejection::Headers(_) => StatusCode::BAD_REQUEST,
            AuthorizationRejection::InvalidToken | AuthorizationRejection::ExpiredToken => {
                StatusCode::UNAUTHORIZED
            }
            AuthorizationRejection::Forbidden(_) => StatusCode::FORBIDDEN,
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
