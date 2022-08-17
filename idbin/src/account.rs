use anyhow::Context;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Query,
    http::{Response, StatusCode},
    Extension, Form,
};

use casbin::{CoreApi, Enforcer};
use idlib::{ApiAuthorize, Authorizations, Authorize};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use tokio_rusqlite::Connection;

use crate::{
    audit::{self, AuditAction},
    error::Error,
    into_response,
};

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPageTemplate {
    username: String,
    email: String,
    permissions: AccountPermissions,
    error: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AccountParams {
    error: Option<String>,
}

pub(crate) async fn page(
    Authorize(username): Authorize,
    Query(params): Query<AccountParams>,
    Extension(Authorizations(auth)): Extension<Authorizations>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let auth = auth.read().await;
    let permissions = get_permissions(&auth, &username)?;
    render_page(username, params.error, permissions, db).await
}

pub(crate) async fn post_page(
    Authorize(name): Authorize,
    Form(update): Form<AccountUpdate>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let redirect = match post_account_impl(update.clone(), db, name).await {
        Ok(()) => "/account#success".into(),
        Err(e) => format!("/account?error={}", urlencoding::encode(&e.to_string())),
    };

    let response = Response::builder()
        .header("Location", &redirect)
        .status(StatusCode::SEE_OTHER)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

fn get_permissions(enforcer: &Enforcer, username: &str) -> anyhow::Result<AccountPermissions> {
    let permissions = enforcer.enforce((username, "permissions", "read"))?;
    let audit = enforcer.enforce((username, "audit", "read"))?;
    let invite = enforcer.enforce((username, "invite", "read"))?;

    Ok(AccountPermissions {
        permissions,
        audit,
        invite,
    })
}

async fn get_email(name: String, db: Connection) -> anyhow::Result<String> {
    let email = db
        .call(move |conn| {
            conn.query_row(
                "SELECT email FROM users WHERE username = ?1",
                params![&name],
                |row| row.get::<_, String>(0),
            )
        })
        .await?;

    Ok(email)
}

struct AccountPermissions {
    audit: bool,
    invite: bool,
    permissions: bool,
}

async fn render_page(
    username: String,
    error: Option<String>,
    permissions: AccountPermissions,
    db: Connection,
) -> Result<Response<BoxBody>, Error> {
    let email = get_email(username.clone(), db).await?;

    let template = AccountPageTemplate {
        username,
        email,
        permissions,
        error,
    };

    Ok(into_response(&template, "html"))
}

#[derive(Clone, Deserialize)]
pub(crate) struct AccountUpdate {
    email: String,
    password: String,
    password2: String,
    old_password: String,
}

pub(crate) async fn post_account(
    Authorize(name): ApiAuthorize,
    Form(update): Form<AccountUpdate>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    post_account_impl(update.clone(), db.clone(), name.clone()).await?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

pub(crate) async fn post_account_impl(
    update: AccountUpdate,
    db: Connection,
    user: String,
) -> anyhow::Result<()> {
    if update.password != update.password2 {
        return Err(anyhow::anyhow!("New passwords are not the same"));
    }

    let username = user.clone();
    let (email, password_hash): (String, String) = db
        .call(move |conn| {
            conn.query_row(
                "SELECT email, password_hash \
                FROM users WHERE username=?1",
                params![&username],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
        })
        .await
        .context("Failed to query username")?
        .context("Failed to find user info")?;

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&password_hash).context("Failed creating hash")?;

    if argon2
        .verify_password(update.old_password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(anyhow::anyhow!("Invalid password"));
    }

    let phc_string = if !update.password.is_empty() {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(update.password.as_bytes(), &salt)
            .context("Failed to hash password")?
            .to_string()
    } else {
        password_hash.clone()
    };

    let changed_password = phc_string != password_hash;
    let changed_email = email != update.email;

    db.call(move |conn| {
        conn.execute(
            "UPDATE users \
            SET \
                password_hash = ?1,
                email = ?2
            WHERE
                username = ?3",
            params![phc_string, update.email, &user],
        )?;

        audit::log(
            conn,
            AuditAction::AccountUpdate(changed_password, changed_email),
            &user,
        )?;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Failed to update account")?;

    Ok(())
}
