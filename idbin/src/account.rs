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

use idlib::{AuthorizeCookie, Payload};
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
    current_page: &'static str,
    username: String,
    email: String,
    admin: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AccountParams {
    error: Option<String>,
}

pub(crate) async fn page(
    AuthorizeCookie(payload): AuthorizeCookie,
    Query(params): Query<AccountParams>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    render_page(payload, params.error, db).await
}

pub(crate) async fn post_page(
    AuthorizeCookie(payload): AuthorizeCookie,
    Form(update): Form<AccountUpdate>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let redirect = match post_account_impl(update.clone(), db, payload.name).await {
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

/*fn get_permissions(enforcer: &Enforcer, username: &str) -> anyhow::Result<AccountPermissions> {
    let permissions = enforcer.enforce((username, "permissions", "read"))?;
    let audit = enforcer.enforce((username, "audit", "read"))?;
    let invite = enforcer.enforce((username, "invite", "read"))?;

    Ok(AccountPermissions {
        permissions,
        audit,
        invite,
    })
}*/

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

async fn render_page(
    payload: Payload,
    error: Option<String>,
    db: Connection,
) -> Result<Response<BoxBody>, Error> {
    let email = get_email(payload.name.clone(), db).await?;

    let template = AccountPageTemplate {
        current_page: "/account",
        username: payload.name,
        email,
        admin: payload.groups.iter().any(|s|s=="admin"),
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
    AuthorizeCookie(payload): AuthorizeCookie,
    Form(update): Form<AccountUpdate>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    post_account_impl(update.clone(), db.clone(), payload.name).await?;

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
