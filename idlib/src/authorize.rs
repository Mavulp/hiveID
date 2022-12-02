use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use axum::{
    body::{boxed, Empty},
    extract::{
        rejection::{ExtensionRejection, TypedHeaderRejection},
        FromRequest, RequestParts,
    },
    http::{header::SET_COOKIE, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use futures::Future;
use jwt::VerifyWithKey;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{
    create_auth_cookie, Cookies, IdpClient, RefreshTokenRequest, RefreshTokenResponse, SecretKey,
    Variables,
};

#[must_use]
pub struct AuthorizeCookie<R: Rule>(pub Payload, pub MaybeRefreshedToken, pub PhantomData<R>);

#[must_use]
pub struct MaybeRefreshedToken(Option<String>);

impl MaybeRefreshedToken {
    pub async fn wrap_future<R: IntoResponse, F: Future<Output = R>>(self, fut: F) -> Response {
        let mut response = fut.await.into_response();

        if let Some(token) = self.0 {
            let cookie = create_auth_cookie(&token);

            match HeaderValue::from_str(&cookie.encoded().to_string()) {
                Ok(value) => {
                    response.headers_mut().insert(SET_COOKIE, value);
                }
                Err(e) => {
                    warn!("Failed to parse cookie value: {e:?}");
                }
            }
        }

        response
    }

    pub fn wrap<R: IntoResponse, F: Fn() -> R>(self, func: F) -> impl IntoResponse {
        let mut response = func().into_response();

        if let Some(token) = self.0 {
            let cookie = create_auth_cookie(&token);

            match HeaderValue::from_str(cookie.value()) {
                Ok(value) => {
                    response.headers_mut().insert(SET_COOKIE, value);
                }
                Err(e) => {
                    warn!("Failed to parse cookie value: {e:?}");
                }
            }
        }

        response
    }
}

pub trait Rule {
    fn verify(groups: &[String]) -> bool;
}

pub struct Has<const G: &'static str>;
pub struct Either<A, B>(PhantomData<(A, B)>);
pub struct Both<A, B>(PhantomData<(A, B)>);

impl<const G: &'static str> Rule for Has<G> {
    fn verify(groups: &[String]) -> bool {
        groups.iter().any(|g| g == G)
    }
}

impl<A: Rule, B: Rule> Rule for Either<A, B> {
    fn verify(groups: &[String]) -> bool {
        A::verify(groups) || B::verify(groups)
    }
}

impl<A: Rule, B: Rule> Rule for Both<A, B> {
    fn verify(groups: &[String]) -> bool {
        A::verify(groups) && B::verify(groups)
    }
}

impl Rule for () {
    fn verify(_groups: &[String]) -> bool {
        true
    }
}

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
impl<B, R: Rule> FromRequest<B> for AuthorizeCookie<R>
where
    B: Send,
{
    type Rejection = AuthorizationRejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Cookies(jar) = Cookies::from_request(req).await.unwrap();

        let Extension(variables) = Extension::<Arc<Variables>>::from_request(req).await?;

        let token = match jar.get("__auth") {
            Some(token) => token,
            None => {
                debug!("Failed to find auth cookie. Redirecting to IDP");

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
        let payload: Payload = token
            .value()
            .verify_with_key(&*secret.0)
            .context("Failed to parse JWT")?;

        let issued_at = Duration::from_secs(payload.issued_at);
        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap();
        let mut new_token = None;

        // tokens are only valid for 60 days
        if now > issued_at + Duration::from_secs(variables.token_duration_seconds as u64) {
            debug!("Token expired, trying to refresh");
            let Extension(idp_client) = Extension::<IdpClient>::from_request(req).await?;

            match try_refresh_token(&variables, idp_client, token.value().to_string()).await {
                Ok(token) => {
                    debug!("Refreshed token");

                    new_token = Some(token);
                }
                Err(e) => {
                    warn!("Failed to refresh token: {e:?}");

                    return Err(AuthorizationRejection::ExpiredToken);
                }
            }
        }

        if !R::verify(&payload.groups) {
            debug!("Invalid permissions in JWT");
            let new_payload: Option<Payload> = new_token
                .as_ref()
                .map(|token| {
                    token
                        .verify_with_key(&*secret.0)
                        .context("Failed to parse JWT")
                })
                .transpose()?;
            if let Some(new_payload) = new_payload {
                if !R::verify(&new_payload.groups) {
                    debug!("Invalid permissions in refreshed JWT");

                    return Err(AuthorizationRejection::Forbidden("todo"));
                } else {
                    debug!("Found correct permissions in refreshed JWT!");
                }
            } else {
                return Err(AuthorizationRejection::Forbidden("todo"));
            }
        }

        Ok(AuthorizeCookie(
            payload,
            MaybeRefreshedToken(new_token),
            PhantomData,
        ))
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

async fn try_refresh_token(
    vars: &Variables,
    IdpClient(client): IdpClient,
    token: String,
) -> anyhow::Result<String> {
    let request = RefreshTokenRequest {
        service: vars.service_name.to_string(),
        token: token.to_string(),
    };

    let response = client
        .post(&vars.idp_refresh_address)
        .json(&request)
        .send()
        .await
        .context("Failed to refresh auth token")?;

    let status = response.status();
    if status != StatusCode::OK {
        return Err(anyhow!(
            "Unexpected status code {status:?} from refreshing token"
        ));
    }

    let response: RefreshTokenResponse = response
        .json()
        .await
        .context("Failed to deserialize token response")?;

    Ok(response.new_token)
}
