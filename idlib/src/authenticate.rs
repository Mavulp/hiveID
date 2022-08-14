use std::{collections::HashMap, pin::Pin, sync::Arc};

use anyhow::Context;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::{FromRequest, Query, RequestParts},
    headers::{authorization::Bearer, Authorization},
    http::{
        header::{COOKIE, LOCATION, SET_COOKIE},
        Response, StatusCode,
    },
    routing::{get, post, put},
    Extension, Router, TypedHeader,
};
use cookie::{Cookie, CookieJar, SameSite};
use futures::Future;
use jwt::VerifyWithKey;
use log::debug;

use crate::{Authorizations, Error, IdpClient, Payload, PermissionResponse, SecretKey, Variables};

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
        .route("/", get(get_auth))
        .route("/", post(post_auth))
        .route("/", put(put_auth))
        .layer(Extension(client));

    if let Some(cb) = cb {
        router = router.layer(Extension(cb));
    }

    router
}

pub fn api_extensions(
    secret_key: SecretKey,
    authorizations: Authorizations,
    variables: Arc<Variables>,
) -> Router {
    Router::new()
        .layer(Extension(secret_key))
        .layer(Extension(authorizations))
        .layer(Extension(variables))
}

/// Consumes the response from the IDP and stores the received token as a
/// cookie in the client's browser.
async fn get_auth(
    Query(params): Query<HashMap<String, String>>,
    Extension(SecretKey(secret_key)): Extension<SecretKey>,
    cb: Option<Extension<AuthCallback>>,
) -> Result<Response<BoxBody>, Error> {
    let redirect_to = params.get("redirect").ok_or(Error::MissingRedirect)?;
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
        .header(LOCATION, redirect_to)
        .header(SET_COOKIE, cookie.encoded().to_string())
        .status(StatusCode::SEE_OTHER)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

/// Refreshes the token from the IDP by sending in a valid token.
async fn post_auth(
    Cookies(jar): Cookies,
    Extension(IdpClient(client)): Extension<IdpClient>,
    Extension(vars): Extension<Arc<Variables>>,
) -> Result<Response<BoxBody>, Error> {
    let token = jar.get("__auth").ok_or(Error::MissingAuthCookie)?;
    let token = token.value().to_string();

    let response = client
        .post(&vars.idp_refresh_address)
        .body(token)
        .send()
        .await
        .context("Failed to refresh auth token")?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if status != StatusCode::OK {
        return Err(Error::BadTokenRefresh(body));
    }

    let cookie = create_auth_cookie(&body);

    let response = Response::builder()
        .header(SET_COOKIE, cookie.encoded().to_string())
        .status(StatusCode::OK)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

/// Updates the authorization data. Should only be called by the IDP when it
/// wants to inform us that some access rules have changed.
async fn put_auth(
    body: String,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Extension(SecretKey(secret_key)): Extension<SecretKey>,
    Extension(auth): Extension<Authorizations>,
) -> Result<Response<BoxBody>, Error> {
    let claims: String = bearer
        .token()
        .verify_with_key(&*secret_key)
        .context("Failed to verify bearer token")?;
    if &claims != "yup" {
        return Err(Error::Unathorized);
    }

    let permissions: PermissionResponse =
        serde_json::de::from_str(&body).context("Failed to parse permission update")?;

    auth.replace_policy(permissions.policy, permissions.group_policy)
        .await
        .context("Failed to replace policy on permission update")?;

    debug!("Updated permissions from IDP");

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(boxed(Empty::new()))
        .unwrap();
    Ok(response)
}

#[derive(Clone)]
pub struct Cookies(pub CookieJar);

#[async_trait::async_trait]
impl<B> FromRequest<B> for Cookies
where
    B: Send,
{
    type Rejection = ();

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let mut jar = CookieJar::new();

        if let Some(Ok(cookie)) = req.headers().get(COOKIE).map(|c| c.to_str()) {
            for cookie in cookie.split(';') {
                if let Ok(cookie) = Cookie::parse_encoded(cookie) {
                    jar.add(cookie.into_owned());
                }
            }
        }

        Ok(Cookies(jar))
    }
}

fn create_auth_cookie<'a>(token: &'a str) -> Cookie<'a> {
    let mut cookie = Cookie::new("__auth", token);
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.make_permanent();

    cookie
}
