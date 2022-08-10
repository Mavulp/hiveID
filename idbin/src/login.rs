use std::{fmt::Write, time::SystemTime};

use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Query,
    http::{Response, StatusCode},
    Extension, Form,
};
use idlib::{Payload, SecretKey};
use jwt::SignWithKey;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use tokio_rusqlite::Connection;
use url::Url;

use crate::{error::Error, into_response, Services};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPageTemplate<'a> {
    service_display: &'a str,
    service: String,
    redirect_to: String,
    error_message: Option<String>,
    username: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct LoginParams {
    service: String,
    redirect_to: String,
    username: Option<String>,
}

pub(crate) async fn page(
    Query(params): Query<LoginParams>,
    Extension(Services(services)): Extension<Services>,
) -> Result<Response<BoxBody>, Error> {
    let service = services
        .get(&params.service)
        .ok_or_else(|| Error::InvalidService(params.service.clone()))?;

    let template = LoginPageTemplate {
        service_display: &service.nice_name,
        service: params.service,
        redirect_to: params.redirect_to,
        error_message: None,
        username: params.username,
    };

    Ok(into_response(&template, "html"))
}

#[derive(Clone, Deserialize)]
pub(crate) struct Login {
    username: String,
    password: String,

    /// The service that is requesting authorization.
    service: String,

    /// The address we will eventually return the client's browser to. The
    /// final redirect is handled by the `auth_endpoint` in order to properly
    /// set the cookies.
    redirect: String,
}

pub(crate) async fn post_login(
    Form(login): Form<Login>,
    Extension(db): Extension<Connection>,
    Extension(secret_key): Extension<SecretKey>,
    Extension(services): Extension<Services>,
) -> Result<Response<BoxBody>, Error> {
    match post_login_impl(login.clone(), db, secret_key, services).await {
        Ok(response) => Ok(response),
        Err(Error::InvalidLogin) => {
            let redirect = format!(
                "/login?service={}&redirect_to={}&username={}#retry",
                login.service, login.redirect, login.username
            );

            let response = Response::builder()
                .header("Location", &redirect)
                .status(StatusCode::SEE_OTHER)
                .body(boxed(Empty::new()))
                .unwrap();

            Ok(response)
        }
        Err(e) => Err(e),
    }
}

pub(crate) async fn post_login_impl(
    login: Login,
    db: Connection,
    SecretKey(secret_key): SecretKey,
    Services(services): Services,
) -> Result<Response<BoxBody>, Error> {
    let result: Option<(String, String)> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT username, password_hash \
                FROM users WHERE username=?1",
                params![login.username],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
        })
        .await
        .context("Failed to query username")?;

    let (username, password_hash) = result.ok_or(Error::InvalidLogin)?;

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&password_hash).context("Failed creating hash")?;

    if argon2
        .verify_password(login.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(Error::InvalidLogin);
    }

    let service = services
        .get(&login.service)
        .ok_or_else(|| Error::InvalidService(login.service.clone()))?;

    let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
    let payload = Payload {
        name: username,
        issued_at: now,
    };
    let token = payload
        .sign_with_key(&*secret_key)
        .context("Failed to sign payload")?;

    let mut url = Url::parse(&service.auth_url).context("Failed to parse URL")?;
    url.query_pairs_mut()
        .clear()
        .append_pair("redirect", &login.redirect)
        .append_pair("token", &token);

    let response = Response::builder()
        .header("Location", url.as_str())
        .status(StatusCode::SEE_OTHER)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}
