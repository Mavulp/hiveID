use std::{collections::HashMap, pin::Pin, sync::Arc};

use anyhow::Context;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::{FromRequest, Query, FromRequestParts},
    http::{
        header::{COOKIE, LOCATION, SET_COOKIE},
        Response, StatusCode, request::Parts,
    },
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};
use cookie::{Cookie, CookieJar, SameSite};
use futures::Future;
use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize};

use crate::{Error, IdpClient, Payload, SecretKey, Variables};

#[derive(Clone)]
pub struct AuthCallback(
    pub  Arc<
        Box<
            dyn Fn(String) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
                + Send
                + Sync,
        >,
    >,
);

pub fn api_route(client: IdpClient, cb: Option<AuthCallback>) -> Router {
    let mut router = Router::new()
        .route("/authorize", get(authorize_with_cookie))
        .route("/revoke", post(revoke_token))
        .route("/logout", post(logout))
        // .route("/", put(put_auth))
        .layer(Extension(client));

    if let Some(cb) = cb {
        router = router.layer(Extension(cb));
    }

    router
}

pub fn api_extensions(secret_key: SecretKey, variables: Arc<Variables>) -> Router {
    Router::new()
        .layer(Extension(secret_key))
        .layer(Extension(variables))
}

/// Consumes the response from the IdP and stores the received token as a
/// cookie in the client's browser.
async fn authorize_with_cookie(
    Query(params): Query<HashMap<String, String>>,
    Extension(SecretKey(secret_key)): Extension<SecretKey>,
    cb: Option<Extension<AuthCallback>>,
) -> Result<Response<BoxBody>, Error> {
    let redirect_uri = params.get("redirect_uri").ok_or(Error::MissingRedirect)?;
    let token = params.get("token").ok_or(Error::MissingToken)?;

    let payload: Payload = token
        .verify_with_key(&*secret_key)
        .context("Failed to verify token")?;
    if let Some(Extension(AuthCallback(cb))) = cb {
        (cb)(payload.name)
            .await
            .context("Failed to run callback function")?;
    }

    // stuff the token in a cookie and send it back with the redirect back to
    // the original page the client started on.
    let cookie = create_auth_cookie(token);

    let response = Response::builder()
        .header(LOCATION, redirect_uri)
        .header(SET_COOKIE, cookie.encoded().to_string())
        .status(StatusCode::FOUND)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

async fn revoke_token() -> Result<impl IntoResponse, Error> {
    Ok(StatusCode::OK)
}

async fn logout() -> Result<impl IntoResponse, Error> {
    let cookie = create_logout_cookie();

    let response = Response::builder()
        .header(LOCATION, "/")
        .header(SET_COOKIE, cookie.encoded().to_string())
        .status(StatusCode::FOUND)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub service: String,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub new_token: String,
}

#[derive(Clone)]
pub struct Cookies(pub CookieJar);

#[async_trait::async_trait]
impl<B> FromRequestParts<B> for Cookies
where
    B: Send + Sync,
{
    type Rejection = ();

    async fn from_request_parts(req: &mut Parts, state: &B) -> Result<Self, Self::Rejection> {
        let mut jar = CookieJar::new();

        if let Some(Ok(cookie)) = req.headers.get(COOKIE).map(|c| c.to_str()) {
            for cookie in cookie.split(';') {
                if let Ok(cookie) = Cookie::parse_encoded(cookie) {
                    jar.add(cookie.into_owned());
                }
            }
        }

        Ok(Cookies(jar))
    }
}

fn create_logout_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::new("__auth", "");
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.make_removal();

    cookie
}

pub fn create_auth_cookie<'a>(token: &'a str) -> Cookie<'a> {
    let mut cookie = Cookie::new("__auth", token);
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.make_permanent();

    cookie
}
