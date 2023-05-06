use std::time::SystemTime;

use anyhow::Context;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use askama::Template;
use axum::{
    body::{boxed, Empty},
    extract::{Path, Query},
    http::{Response, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Extension, Form, Json, Router,
};
use idlib::{AuthorizeCookie, Has, Jwt};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio_rusqlite::Connection;
use tracing::debug;
use utoipa::ToSchema;

use crate::{
    audits::{self, AuditAction},
    error::Error,
    internal_error, into_response,
};

pub fn api_route() -> Router {
    Router::new()
        .route("/", post(create_new_invite))
        .route("/", get(get_all_invite_infos))
        .route("/:id", get(get_invite_info))
        .route("/:id", post(register_with_invite_link))
        .route("/:id", delete(delete_invite))
}

/// Information about an invite.
#[derive(Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InviteInfo {
    /// The unique ID of the invite. This ID is used when registering.
    key: String,

    /// Who created the invite.
    created_by: String,

    /// When the invite was created.
    #[serde(with = "time::serde::timestamp")]
    created: OffsetDateTime,

    /// Who the invite was redeemed by.
    used_by: Option<String>,

    /// When the invite was redeemed.
    #[serde(with = "time::serde::timestamp::option")]
    used: Option<OffsetDateTime>,
}

/// A request to create a new invite link.
#[derive(Deserialize, Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvite {
    /// A list of services that the one who redeems the invite link should get access to.
    services: Vec<String>,
}

/// A request to register an account.
#[derive(Deserialize, Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAccount {
    email: String,
    username: String,
    password: String,
}

type AdminJwt = Jwt<Has<"">>;

/// Registers an account using the provided invite ID.
#[utoipa::path(
    post,
    path = "/api/v2/invites/{key}",
    request_body = RegisterAccount,
    params(
        ("key" = String, Path, description = "The invite ID")
    ),
    responses(
        (status = 200, description = "Succesfully registered an account")
    ),
    security(
        ()
    )
)]
pub(crate) async fn register_with_invite_link(
    Extension(db): Extension<Connection>,
    Path(key): Path<String>,
    Json(create): Json<RegisterAccount>,
) -> Result<(), (StatusCode, String)> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let phc_string = argon2
        .hash_password(create.password.as_bytes(), &salt)
        .context("Failed to hash password")
        .map_err(internal_error)?
        .to_string();
    let now = SystemTime::UNIX_EPOCH
        .elapsed()
        .context("Failed to get elapsed time")
        .map_err(internal_error)?
        .as_secs();

    let username = create.username.clone();

    db.call(move |conn| {
        // TODO: transaction?
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at, invite_key, email) \
            VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&create.username, phc_string, now, &key, create.email],
        )
        .context("Failed to insert new user")?;

        let roles = get_default_roles_for_invite(conn, &key);

        for (service, role) in roles {
            debug!("Assigning role {service:?}/{role:?} to {username:?}");

            conn.execute(
                "INSERT INTO user_roles (username, service, role) \
                VALUES (?1, ?2, ?3)",
                params![&username, &service, &role],
            )
            .context("Failed to insert user role")?;
        }

        audits::log(
            conn,
            AuditAction::ConsumeInvite(key.clone()),
            &create.username,
        )?;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Failed to insert new account")
    .map_err(internal_error)?;

    Ok(())
}

/// Creates a new invite link.
#[utoipa::path(
    post,
    path = "/api/v2/invites",
    request_body = CreateInvite,
    responses(
        (status = 200, description = "Invitation was succesfully created", body = [InviteInfo])
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn create_new_invite(
    Jwt(payload, ..): AdminJwt,
    Extension(db): Extension<Connection>,
    Json(create): Json<CreateInvite>,
) -> Result<Json<InviteInfo>, (StatusCode, String)> {
    let info = create_invite_link(db, payload.name, create.services.join(","))
        .await
        .map_err(internal_error)?;

    Ok(Json(info))
}

/// List all invites.
#[utoipa::path(
    get,
    path = "/api/v2/invites",
    responses(
        (status = 200, description = "List all invites successfully", body = [Vec<InviteInfo>])
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn get_all_invite_infos(
    _jwt: AdminJwt,
    Extension(db): Extension<Connection>,
) -> Result<Json<Vec<InviteInfo>>, (StatusCode, String)> {
    let infos = get_links(db)
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(
            |Link {
                 key,
                 created_by,
                 created,
                 used_by,
                 used,
             }| InviteInfo {
                key,
                created_by,
                created,
                used_by,
                used,
            },
        )
        .collect::<Vec<InviteInfo>>();

    Ok(Json(infos))
}

/// List invite information.
#[utoipa::path(
    get,
    path = "/api/v2/invites/{key}",
    params(
        ("key" = String, Path, description = "The invite ID")
    ),
    responses(
        (status = 200, description = "List the invite successfully", body = [InviteInfo])
    ),
    security(
        (),
    )
)]
pub(crate) async fn get_invite_info(
    Extension(db): Extension<Connection>,
    Path(key): Path<String>,
) -> Result<Json<InviteInfo>, (StatusCode, String)> {
    let info = get_links(db)
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(
            |Link {
                 key,
                 created_by,
                 created,
                 used_by,
                 used,
             }| InviteInfo {
                key,
                created_by,
                created,
                used_by,
                used,
            },
        )
        .find(|i| i.key == key)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("Couldn't find invite with id '{key}'"),
            )
        })?;

    Ok(Json(info))
}

/// Delete an existing and unclaimed invitation.
#[utoipa::path(
    delete,
    path = "/api/v2/invites/{key}",
    params(
        ("key" = String, Path, description = "The invite ID")
    ),
    responses(
        (status = 200, description = "Invitation was succesfully removed")
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn delete_invite(
    Jwt(payload, ..): AdminJwt,
    Extension(db): Extension<Connection>,
    Path(key): Path<String>,
) -> Result<(), (StatusCode, String)> {
    db.call(move |conn| {
        conn.execute(
            "DELETE FROM user_invites \
            WHERE \"key\" = ?1 AND NOT EXISTS (SELECT 1 FROM users WHERE invite_key = ?1)",
            params![&key],
        )
        .context("Failed to delete invite")?;

        audits::log(conn, AuditAction::DeleteInvite(key), &payload.name)?;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(internal_error)?;

    Ok(())
}

pub(crate) async fn create_invite_link(
    db: Connection,
    username: String,
    services: String,
) -> Result<InviteInfo, Error> {
    let info = db
        .call(move |conn| {
            let key = create_invite_key();
            let now = OffsetDateTime::now_utc().unix_timestamp();
            conn.execute(
                "INSERT INTO user_invites (key, created_by, created_at, services)
            VALUES (?1, ?2, ?3, ?4)",
                params![&key, &username, now, services],
            )
            .context("Failed to delete invite")?;

            audits::log(conn, AuditAction::CreateInvite(key.clone()), &username)?;

            let info = InviteInfo {
                key,
                created_by: username,
                created: OffsetDateTime::now_utc(),
                used_by: None,
                used: None,
            };

            Ok::<InviteInfo, anyhow::Error>(info)
        })
        .await?;

    Ok(info)
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

fn create_invite_key() -> String {
    blob_uuid::random_blob()
}

#[derive(Deserialize)]
struct DbLinkInfo {
    key: String,
    created_by: String,
    created_at: i64,
    used_by: Option<String>,
    used_at: Option<i64>,
}

async fn get_links(db: Connection) -> anyhow::Result<Vec<Link>> {
    db.call(move |conn| {
        let mut stmt = conn
            .prepare(
                "SELECT \
                ui.\"key\", \
                ui.created_by, \
                ui.created_at, \
                u.username AS used_by, \
                u.created_at AS used_at \
            FROM user_invites ui \
            LEFT OUTER JOIN \
                users u \
            ON \
                ui.\"key\" = u.invite_key \
            ORDER BY ui.created_at DESC",
            )
            .context("Failed to prepare link statement")?;

        let links = stmt
            .query_map(params![], |row| {
                let info = serde_rusqlite::from_row::<DbLinkInfo>(row).unwrap();

                let link = Link {
                    key: info.key,
                    created_by: info.created_by,
                    created: OffsetDateTime::from_unix_timestamp(info.created_at).unwrap(),
                    used_by: info.used_by,
                    used: info
                        .used_at
                        .map(|at| OffsetDateTime::from_unix_timestamp(at).unwrap()),
                };

                Ok(link)
            })
            .context("Failed to query invite links")?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to collect links")?;

        Ok(links)
    })
    .await
}

// TODO: remove old stuff below
//
//

pub fn router() -> Router {
    Router::new()
        .route("/", get(page))
        .route("/create", post(create_page))
        .route("/delete", post(delete_page))
}

struct Link {
    key: String,
    created_by: String,
    created: OffsetDateTime,
    used_by: Option<String>,
    used: Option<OffsetDateTime>,
}

#[derive(Template)]
#[template(path = "invite.html")]
struct InvitePageTemplate {
    current_page: &'static str,
    admin: bool,
    links: Vec<Link>,
    // services: &'a HashMap<String, Service>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct InviteParams {
    error: Option<String>,
}

pub(crate) async fn page(
    AuthorizeCookie(_payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Query(params): Query<InviteParams>,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            let links = get_links(db).await?;

            let template = InvitePageTemplate {
                current_page: "/admin/invite",
                admin: true,
                links,
                error: params.error,
            };

            Ok::<_, Error>(into_response(&template, "html"))
        })
        .await
}

#[derive(Deserialize)]
pub(crate) struct DeleteForm {
    key: String,
}

pub(crate) async fn delete_page(
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
    Form(DeleteForm { key }): Form<DeleteForm>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            let redirect = match delete_invite_impl(key, db, payload.name).await {
                Ok(()) => "/admin/invite#removed".into(),
                Err(e) => format!(
                    "/admin/invite?error={}",
                    urlencoding::encode(&e.to_string())
                ),
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

pub(crate) async fn delete_invite_impl(
    key: String,
    db: Connection,
    name: String,
) -> Result<(), Error> {
    db.call(move |conn| {
        conn.execute(
            "DELETE FROM user_invites \
            WHERE \"key\" = ?1 AND NOT EXISTS (SELECT 1 FROM users WHERE invite_key = ?1)",
            params![&key],
        )
        .context("Failed to delete invite")?;

        audits::log(conn, AuditAction::DeleteInvite(key), &name)?;

        Ok::<(), anyhow::Error>(())
    })
    .await?;

    Ok(())
}

pub(crate) async fn create_page(
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
    Form(services): Form<Vec<(String, String)>>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            let services = services
                .into_iter()
                .filter_map(|(s, v)| (v == "true").then(|| s))
                .collect::<Vec<_>>();
            let services = services.join(",");

            let redirect = match create_invite_link(db, payload.name, services).await {
                Ok(_) => "/admin/invite#added".into(),
                Err(e) => format!(
                    "/admin/invite?error={}",
                    urlencoding::encode(&e.to_string())
                ),
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
