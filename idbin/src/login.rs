use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Query,
    http::{Response, StatusCode},
    Extension, Form,
};
use log::*;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use tokio_rusqlite::Connection;

use crate::{
    error::Error,
    into_response,
    services::{get_service, Service},
    token,
};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPageTemplate {
    service: Service,
    redirect_to: String,
    username: Option<String>,
    login_failed: bool,
}

#[derive(Deserialize)]
pub(crate) struct LoginParams {
    service: String,
    redirect_to: String,
    username: Option<String>,
    #[serde(default)]
    login_failed: bool,
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
        .await?
        .ok_or_else(|| Error::InvalidService(params.service.clone()))?;

    let template = LoginPageTemplate {
        service,
        redirect_to: params.redirect_to,
        login_failed: params.login_failed,
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
    Extension(db): Extension<Connection>,
    Form(login): Form<Login>,
) -> Result<Response<BoxBody>, Error> {
    match post_login_impl(login.clone(), db).await {
        Ok(response) => Ok(response),
        Err(Error::InvalidLogin) => {
            let redirect = format!(
                "/login?service={}&redirect_to={}&username={}&login_failed={}",
                login.service,
                login.redirect,
                login.username,
                urlencoding::encode("true")
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

    let service = get_service(&db, login.service.clone())
        .await?
        .ok_or_else(|| Error::InvalidService(login.service.clone()))?;

    let token = generate_jwt_for_user_and_service(db, username, &service)
        .await
        .context("Failed to generate JWT")?;

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

pub async fn generate_jwt_for_user_and_service(
    db: Connection,
    username: String,
    service: &Service,
) -> anyhow::Result<String> {
    let groups = get_groups_for_user(&db, username.clone(), service.name.clone()).await;

    Ok(token::generate_jwt(username, groups, &service.secret)?)
}
