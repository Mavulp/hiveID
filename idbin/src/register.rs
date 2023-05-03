use std::time::SystemTime;

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
    routing::{get, post},
    Extension, Form, Router,
};

use log::{debug, warn};
use rusqlite::params;
use serde::Deserialize;

use crate::{
    audit::{self, AuditAction},
    error::Error,
    into_response, Connection,
};

pub fn router() -> Router {
    Router::new()
        .route("/", get(page))
        .route("/", post(post_page))
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterPageTemplate {
    invite_key: String,
    inviter: String,
    username: Option<String>,
    error_message: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RegisterParams {
    invite: String,
    username: Option<String>,
    error: Option<String>,
}

pub(crate) async fn page(
    Query(params): Query<RegisterParams>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let inviter = get_inviter(params.invite.clone(), db).await?;

    let template = RegisterPageTemplate {
        invite_key: params.invite,
        inviter,
        username: params.username,
        error_message: params.error,
    };

    Ok(into_response(&template, "html"))
}

async fn get_inviter(key: String, db: Connection) -> anyhow::Result<String> {
    let inviter = db
        .call(move |conn| {
            conn.query_row(
                "SELECT \
                created_by \
            FROM user_invites \
            WHERE key = ?1 AND NOT EXISTS (SELECT 1 FROM users WHERE invite_key = \"key\")",
                params![&key],
                |row| row.get::<_, String>(0),
            )
        })
        .await
        .context("Failed to get inviter")?;

    Ok(inviter)
}

fn get_default_roles_for_invite(
    conn: &mut rusqlite::Connection,
    key: &str,
) -> Vec<(String, String)> {
    let mut stmt = conn
        .prepare(
            "SELECT service, role FROM user_invite_default_roles \
            WHERE \"key\" = ?1",
        )
        .unwrap();

    stmt.query_map(params![&key], |row| {
        Ok((
            row.get::<_, String>(0).unwrap(),
            row.get::<_, String>(1).unwrap(),
        ))
    })
    .unwrap()
    .collect::<Result<Vec<(String, String)>, _>>()
    .unwrap()
}

#[derive(Clone, Deserialize)]
pub(crate) struct Register {
    invite: String,
    email: String,
    username: String,
    password: String,
    password2: String,
}

pub(crate) async fn post_page(
    Extension(db): Extension<Connection>,
    Form(register): Form<Register>,
) -> Result<Response<BoxBody>, Error> {
    let redirect = match post_register_impl(register.clone(), db).await {
        Ok(()) => "/".into(),
        Err(e) => {
            warn!(
                "Failed to register account with invite ID {:?}: {:?}",
                register.username, e
            );

            format!(
                "/register?invite={}&username={}&error={}",
                register.invite,
                register.username,
                urlencoding::encode(&e.to_string())
            )
        }
    };

    let response = Response::builder()
        .header("Location", &redirect)
        .status(StatusCode::SEE_OTHER)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

pub(crate) async fn post_register_impl(register: Register, db: Connection) -> Result<(), Error> {
    if register.password != register.password2 {
        return Err(Error::PasswordMismatch);
    }

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

    let username = register.username.clone();

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at, invite_key, email) \
            VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &register.username,
                phc_string,
                now,
                &register.invite,
                register.email
            ],
        )
        .context("Failed to insert new user")?;

        let roles = get_default_roles_for_invite(conn, &register.invite);

        for (service, role) in roles {
            debug!("Assigning role {service:?}/{role:?} to {username:?}");

            conn.execute(
                "INSERT INTO user_roles (username, service, role) \
                VALUES (?1, ?2, ?3)",
                params![&username, &service, &role],
            )
            .context("Failed to insert user role")?;
        }

        audit::log(
            conn,
            AuditAction::ConsumeInvite(register.invite.clone()),
            &register.username,
        )?;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Failed to insert new account")?;

    Ok(())
}
