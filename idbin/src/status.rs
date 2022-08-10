use std::{
    fmt::Write,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::Context;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    http::{Response, StatusCode},
    Extension, Form,
};
use futures::{stream, StreamExt};
use reqwest::Client;
use rusqlite::params;
use serde::Deserialize;
use tokio::{sync::RwLock, time::sleep};
use tokio_rusqlite::Connection;

use crate::{error::Error, into_response, Service, Services};

pub async fn status_poll_loop(Statuses(statuses): Statuses, Services(services): Services) {
    let client = Client::new();

    loop {
        let services = services
            .iter()
            .map(|(n, s)| (n.clone(), s.clone()))
            .collect::<Vec<(String, Service)>>();
        let new_statuses = stream::iter(services)
            .map(|(_name, service)| {
                let client = &client;
                let url = service.url.clone();
                let health_url = service.health_url.clone();
                async move {
                    let response = client.get(health_url).send().await;
                    Status {
                        name: service.nice_name.clone(),
                        url,
                        code: response.ok().map(|r| r.status()),
                    }
                }
            })
            .buffer_unordered(5)
            .collect::<Vec<Status>>()
            .await;

        *statuses.write().await = new_statuses;

        sleep(Duration::from_secs(60)).await;
    }
}

pub struct Status {
    name: String,
    url: String,
    code: Option<StatusCode>,
}

impl Status {
    fn is_ok(&self) -> bool {
        self.code.map(|c| c.is_success()).unwrap_or(false)
    }
}

#[derive(Clone)]
pub struct Statuses(pub Arc<RwLock<Vec<Status>>>);

#[derive(Template)]
#[template(path = "status.html")]
struct StatusPageTemplate<'a> {
    statuses: &'a [Status],
}

pub(crate) async fn page(
    Extension(Statuses(statuses)): Extension<Statuses>,
) -> Result<Response<BoxBody>, Error> {
    let statuses = statuses.read().await;
    let template = StatusPageTemplate {
        statuses: &statuses,
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
