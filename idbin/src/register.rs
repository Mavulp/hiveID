use std::{fmt::Write, time::SystemTime};

use anyhow::Context;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Query,
    http::{Response, StatusCode},
    Extension, Form,
};

use rusqlite::params;
use serde::Deserialize;
use tokio_rusqlite::Connection;

use crate::{error::Error, into_response};

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterPageTemplate {
    username: Option<String>,
    error_message: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RegisterParams {
    username: Option<String>,
    error: Option<String>,
}

pub(crate) async fn page(Query(params): Query<RegisterParams>) -> Result<Response<BoxBody>, Error> {
    let template = RegisterPageTemplate {
        username: params.username,
        error_message: params.error,
    };

    Ok(into_response(&template, "html"))
}

#[derive(Clone, Deserialize)]
pub(crate) struct Register {
    username: String,
    password: String,
}

pub(crate) async fn post_register(
    Form(register): Form<Register>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let redirect = match post_register_impl(register.clone(), db).await {
        Ok(()) => "/register#success".into(),
        Err(e) => format!(
            "/register?username={}&error={}",
            register.username,
            urlencoding::encode(&e.to_string())
        ),
    };

    let response = Response::builder()
        .header("Location", &redirect)
        .status(StatusCode::SEE_OTHER)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

pub(crate) async fn post_register_impl(register: Register, db: Connection) -> Result<(), Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let phc_string = argon2
        .hash_password(register.password.as_bytes(), &salt)
        .context("Failed to hash password")?
        .to_string();
    let now = SystemTime::UNIX_EPOCH
        .elapsed()
        .context("Failed to get elapsed time")?
        .as_secs();

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            params![register.username, phc_string, now],
        )
    })
    .await
    .context("Failed to insert new account")?;

    Ok(())
}
