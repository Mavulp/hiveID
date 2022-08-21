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
    Extension, Form,
};

use casbin::RbacApi;
use idlib::Authorizations;
use log::debug;
use rusqlite::params;
use serde::Deserialize;

use crate::{
    audit::{self, AuditAction},
    error::Error,
    into_response, Connection, Services,
};

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

#[derive(Clone, Deserialize)]
pub(crate) struct Register {
    invite: String,
    email: String,
    username: String,
    password: String,
    password2: String,
}

pub(crate) async fn post_page(
    Form(register): Form<Register>,
    Extension(db): Extension<Connection>,
    Extension(auth): Extension<Authorizations>,
    Extension(services): Extension<Services>,
) -> Result<Response<BoxBody>, Error> {
    let redirect = match post_register_impl(register.clone(), auth, services, db).await {
        Ok(()) => "/".into(),
        Err(e) => format!(
            "/register?invite={}&username={}&error={}",
            register.invite,
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

pub(crate) async fn post_register_impl(
    register: Register,
    Authorizations(auth): Authorizations,
    Services(services): Services,
    db: Connection,
) -> Result<(), Error> {
    if register.username.starts_with("role_") {
        return Err(anyhow::anyhow!("Invalid username").into());
    }

    if register.password != register.password2 {
        return Err(anyhow::anyhow!("Passwords do not match").into());
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
    let mut auth = auth.write().await;
    let service_access = db.call(move |conn| {
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at, invite_key, email) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&register.username, phc_string, now, &register.invite, register.email],
        ).context("Failed to insert new user")?;

        let service_access: String = conn.query_row("SELECT services FROM user_invites WHERE \"key\" = ?1", params![&register.invite], |row| row.get(0))?;

        audit::log(conn, AuditAction::ConsumeInvite(register.invite.clone()), &register.username)?;

        Ok::<String, anyhow::Error>(service_access)
    })
    .await
    .context("Failed to insert new account")?;

    let service_access = service_access.split(',').collect::<Vec<_>>();
    for service in service_access {
        if let Some(roles) = services.get(service).and_then(|s| s.default_roles.as_ref()) {
            for role in roles {
                debug!("Assigning role {role:?} to {username:?}");

                auth.add_role_for_user(&username, role, None)
                    .await
                    .context("Failed to add default roles for user")?;
            }
        }
    }

    Ok(())
}
