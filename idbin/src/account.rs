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
    response::{IntoResponse, Json},
    routing::{get, post, put},
    Extension, Form, Router,
};
use idlib::{AuthorizeCookie, Jwt, Payload};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio_rusqlite::Connection;
use utoipa::ToSchema;

use crate::{
    audit::{self, AuditAction},
    error::Error,
    internal_error, into_response,
};

pub fn api_route() -> Router {
    Router::new()
        .route("/", get(get_account_info))
        .route("/", put(update_account_info))
}

/// The account information.
#[derive(Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    /// The account's username.
    username: String,
    /// The email address associated with the account.
    email: String,
}

/// List the account info.
#[utoipa::path(
    get,
    path = "/api/v2/account",
    responses(
        (status = 200, description = "List account info successfully", body = [AccountInfo])
    ),
    security(
        ("api_key" = [])
    )
)]
pub(crate) async fn get_account_info(
    Jwt(payload, ..): Jwt<()>,
    Extension(db): Extension<Connection>,
) -> Result<Json<AccountInfo>, (StatusCode, String)> {
    let email = get_email(payload.name.clone(), db)
        .await
        .map_err(internal_error)?;

    Ok(Json(AccountInfo {
        username: payload.name,
        email,
    }))
}

/// Account information update.
#[derive(Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfoUpdate {
    /// The new email to be set.
    new_email: Option<String>,
    /// The password to be updated.
    new_password: Option<PasswordUpdate>,
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasswordUpdate {
    /// The old password.
    old_password: String,
    /// The new password to be used.
    new_password: String,
}

/// Updates the account information.
#[utoipa::path(
    put,
    path = "/api/v2/account",
    request_body = AccountInfoUpdate,
    responses(
        (status = 200, description = "The account information was updated succesfully")
    ),
    security(
        ("api_key" = [])
    )
)]
#[axum_macros::debug_handler]
pub(crate) async fn update_account_info(
    Jwt(payload, ..): Jwt<()>,
    Extension(db): Extension<Connection>,
    Json(update): Json<AccountInfoUpdate>,
) -> Result<StatusCode, (StatusCode, String)> {
    if update.new_email.is_none() && update.new_password.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Nothing to update".into()));
    }

    update_account(payload.name, update, db)
        .await
        .map_err(internal_error)?;

    Ok(StatusCode::OK)
}

async fn update_account(
    username: String,
    update: AccountInfoUpdate,
    db: Connection,
) -> anyhow::Result<()> {
    let user = username.clone();
    let password_hash: String = db
        .call(move |conn| {
            conn.query_row(
                "SELECT password_hash \
                FROM users WHERE username=?1",
                params![&user],
                |row| Ok(row.get(0)?),
            )
            .optional()
        })
        .await
        .context("Failed to query username")?
        .context("Failed to find user info")?;

    let changed_email = update.new_email.is_some();
    let changed_password = update.new_password.is_some();

    let new_password_phc_string = if let Some(PasswordUpdate {
        old_password,
        new_password,
    }) = update.new_password
    {
        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(&password_hash).context("Failed creating hash")?;

        if argon2
            .verify_password(old_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(anyhow::anyhow!("Invalid password"));
        }

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Some(
            argon2
                .hash_password(new_password.as_bytes(), &salt)
                .context("Failed to hash password")?
                .to_string(),
        )
    } else {
        None
    };

    db.call(move |conn| {
        if let Some(email) = update.new_email {
            conn.execute(
                "UPDATE users \
                SET \
                    email = ?1
                WHERE
                    username = ?2",
                params![email, &username],
            )?;
        }

        if let Some(phc_string) = new_password_phc_string {
            conn.execute(
                "UPDATE users \
                SET \
                    password_hash = ?1,
                WHERE
                    username = ?2",
                params![phc_string, &username],
            )?;
        }

        audit::log(
            conn,
            AuditAction::AccountUpdate(changed_password, changed_email),
            &username,
        )?;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Failed to update account")?;

    Ok(())
}

// TODO: remove old stuff below
//
//

pub fn router() -> Router {
    Router::new()
        .route("/", get(page))
        .route("/", post(post_page))
}

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
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<()>,
    Query(params): Query<AccountParams>,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(render_page(payload, params.error, db))
        .await
}

pub(crate) async fn post_page(
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<()>,
    Extension(db): Extension<Connection>,
    Form(update): Form<AccountUpdate>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            let result = update_account(
                payload.name,
                AccountInfoUpdate {
                    new_email: Some(update.email),
                    new_password: Some(PasswordUpdate {
                        old_password: update.old_password,
                        new_password: update.password,
                    }),
                },
                db,
            )
            .await;

            let redirect = match result {
                Ok(()) => "/account#success".into(),
                Err(e) => format!("/account?error={}", urlencoding::encode(&e.to_string())),
            };

            let response = Response::builder()
                .header("Location", &redirect)
                .status(StatusCode::SEE_OTHER)
                .body(boxed(Empty::new()))
                .unwrap();

            Ok::<_, Error>(response)
        })
        .await
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
        admin: payload.groups.iter().any(|s| s == "admin"),
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
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<()>,
    Extension(db): Extension<Connection>,
    Form(update): Form<AccountUpdate>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            update_account(
                payload.name,
                AccountInfoUpdate {
                    new_email: Some(update.email),
                    new_password: Some(PasswordUpdate {
                        old_password: update.old_password,
                        new_password: update.password,
                    }),
                },
                db,
            )
            .await?;
            // post_account_impl(update.clone(), db.clone(), payload.name).await?;

            let response = Response::builder()
                .status(StatusCode::OK)
                .body(boxed(Empty::new()))
                .unwrap();

            Ok::<_, Error>(response)
        })
        .await
}
