use std::time::SystemTime;

use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Query,
    http::{Response, StatusCode},
    Extension, Form,
};
use hmac::{Hmac, Mac};
use idlib::{Payload};
use jwt::SignWithKey;
use log::debug;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use sha2::Sha256;
use tokio_rusqlite::Connection;


use crate::{error::Error, into_response};

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

struct Service {
    name: String,
    nice_name: String,
    secret: String,
    callback_url: String,
}

async fn get_service(db: &Connection, service_name: String) -> Option<Service> {
    db.call(move |conn| {
        conn.query_row(
            "SELECT name, nice_name, secret, callback_url FROM services WHERE name = ?1",
            params![&service_name],
            |row| {
                Ok(Service {
                    name: row.get(0).unwrap(),
                    nice_name: row.get(1).unwrap(),
                    secret: row.get(2).unwrap(),
                    callback_url: row.get(3).unwrap(),
                })
            },
        )
        .optional()
        .unwrap()
    })
    .await
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

pub(crate) async fn page(
    Query(params): Query<LoginParams>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let service = get_service(&db, params.service.clone())
        .await
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
) -> Result<Response<BoxBody>, Error> {
    match post_login_impl(login.clone(), db).await {
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
) -> Result<Response<BoxBody>, Error> {
    let service = get_service(&db, login.service.clone())
        .await
        .ok_or_else(|| Error::InvalidService(login.service.clone()))?;

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

            return Err(Error::InvalidLogin);
        }
    };

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&password_hash).context("Failed creating hash")?;

    if argon2
        .verify_password(login.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        debug!("Failed to verify password for {username:?}");

        return Err(Error::InvalidLogin);
    }

    let groups = get_groups_for_user(&db, username.clone(), service.name).await;

    let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
    let payload = Payload {
        name: username,
        issued_at: now,
        groups,
    };

    let secret_key = base64::decode(&service.secret).context("Failed to decode service secret")?;
    let secret_key = Hmac::<Sha256>::new_from_slice(&secret_key)
        .context("Failed to create HMAC from secret key")?;

    let token = payload
        .sign_with_key(&secret_key)
        .context("Failed to sign payload")?;

    let url = format!(
        "{}?redirect_uri={}&token={}",
        service.callback_url,
        urlencoding::encode(&login.redirect),
        urlencoding::encode(&token)
    );

    let response = Response::builder()
        .header("Location", url.as_str())
        .status(StatusCode::SEE_OTHER)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}
