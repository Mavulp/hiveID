use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Json,
    http::{Response, StatusCode},
    routing::post,
    Extension, Router,
};
use base64::Engine;
use hmac::{Hmac, Mac};
use idlib::Payload;
use jwt::VerifyWithKey;
use log::debug;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio_rusqlite::Connection;
use utoipa::ToSchema;

use crate::{
    error::Error,
    internal_error,
    services::{get_service, Service},
    token,
};

pub fn api_route() -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh))
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginRequest {
    username: String,
    password: String,

    /// The service that is requesting authorization.
    service: String,

    /// The address we will eventually return the client's browser to. The
    /// final redirect is handled by the `auth_endpoint` in order to properly
    /// set the cookies.
    redirect: String,
}

/// Logs in to a service.
///
/// The response to this request is a 302  redirect to the given redirect parameter. This
/// redirected URL contains the JWT for the successfull login request. It is intended that the
/// handler of the URL should determine what to do with the auth token (eg. put in a cookie or
/// local storage).
#[utoipa::path(
    post,
    path = "/api/v2/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 302, description = "Succesfully logged in and redirected to the service requiring authentication.")
    )
)]
pub(crate) async fn login(
    Extension(db): Extension<Connection>,
    Json(login): Json<LoginRequest>,
) -> Result<Response<BoxBody>, (StatusCode, String)> {
    let username = login.username.clone();

    let result: Option<(String, String)> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT username, password_hash \
                FROM users WHERE username=?1",
                params![login.username],
                |row| Ok((row.get(0).unwrap(), row.get(1).unwrap())),
            )
            .optional()
            .unwrap()
        })
        .await;

    let (username, password_hash) = match result {
        Some((username, password_hash)) => (username, password_hash),
        None => {
            debug!("Failed to find {:?}", username);

            return Err((StatusCode::BAD_REQUEST, "No such user".into()));
        }
    };

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&password_hash)
        .context("Failed creating hash")
        .map_err(internal_error)?;

    if argon2
        .verify_password(login.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        debug!("Failed to verify password for {username:?}");

        return Err((StatusCode::BAD_REQUEST, "Invalid login".into()));
    }

    let service = get_service(&db, login.service.clone())
        .await
        .map_err(internal_error)?
        .ok_or_else(|| Error::InvalidService(login.service.clone()))
        .map_err(internal_error)?;

    let token = generate_jwt_for_user_and_service(db, username, &service)
        .await
        .context("Failed to generate JWT")
        .map_err(internal_error)?;

    let url = format!(
        "{}?redirect_uri={}&token={}",
        service.callback_url,
        urlencoding::encode(&login.redirect),
        urlencoding::encode(&token)
    );

    let response = Response::builder()
        .header("Location", url.as_str())
        .status(StatusCode::FOUND)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshRequest {
    /// The auth token that should be refreshed.
    auth_token: String,

    /// The service that is requesting authorization.
    service: String,
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshResponse {
    /// The new refreshed auth token.
    new_auth_token: String,
}

/// Refreshes an auth token for a service.
///
/// An auth token should be refreshed when it is deemed out-of-date by the service requiring it.
/// This may be due to the roles for the user have changed on idbin.
#[utoipa::path(
    post,
    path = "/api/v2/auth/refresh",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Succesfully refreshed token.", body = [RefreshResponse])
    )
)]
pub(crate) async fn refresh(
    Extension(db): Extension<Connection>,
    Json(refresh): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    debug!("Refreshing authentication");

    let service = get_service(&db, refresh.service.clone())
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("No such service {}", refresh.service),
            )
        })?;

    let secret_key = base64::engine::general_purpose::STANDARD
        .decode(&service.secret)
        .context("Failed to decode service secret")
        .map_err(internal_error)?;
    let secret_key = Hmac::<Sha256>::new_from_slice(&secret_key)
        .context("Failed to create HMAC from secret key")
        .map_err(internal_error)?;

    let payload: Payload = refresh
        .auth_token
        .verify_with_key(&secret_key)
        .context("Failed to parse JWT")
        .map_err(internal_error)?;

    debug!(
        "Refreshing authentication for {} with service {}",
        payload.name, refresh.service
    );

    let new_auth_token = generate_jwt_for_user_and_service(db, payload.name, &service)
        .await
        .context("Failed to create new JWT token")
        .map_err(internal_error)?;

    Ok(Json(RefreshResponse { new_auth_token }))
}

async fn get_groups_for_user(db: &Connection, username: String, service: String) -> Vec<String> {
    db.call(move |conn| {
        let mut stmt = conn
            .prepare("SELECT role FROM user_roles WHERE username = ?1 AND service = ?2")
            .unwrap();

        stmt.query_map(params![&username, service], |row| Ok(row.get(0).unwrap()))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    })
    .await
}

pub async fn generate_jwt_for_user_and_service(
    db: Connection,
    username: String,
    service: &Service,
) -> anyhow::Result<String> {
    let groups = get_groups_for_user(&db, username.clone(), service.name.clone()).await;

    Ok(token::generate_jwt(username, groups, &service.secret)?)
}
