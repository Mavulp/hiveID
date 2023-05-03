use std::time::Duration;

use anyhow::Context;
use askama::Template;
use axum::{
    body::{boxed, Empty},
    extract::Query,
    http::{Response, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Extension, Form, Router,
};

use idlib::{AuthorizeCookie, Has};

use serde::Deserialize;

use rusqlite::params;
use time::OffsetDateTime;
use tokio_rusqlite::Connection;

use crate::{
    audit::{self, AuditAction},
    error::Error,
    into_response,
};

pub fn router() -> Router {
    Router::new()
        .route("/", get(page))
        .route("/create", post(create_page))
        .route("/delete", post(delete_page))
}

struct Link {
    key: String,
    created_by: String,
    created_ago: Duration,
    used_by: Option<String>,
    used_ago: Option<Duration>,
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

mod filters {
    use relativetime::NegativeRelativeTime;
    use std::time::Duration;

    pub fn duration(duration: &Duration) -> ::askama::Result<String> {
        Ok(duration.to_relative_in_past())
    }
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

        let now = OffsetDateTime::now_utc();
        let links = stmt
            .query_map(params![], |row| {
                let info = serde_rusqlite::from_row::<DbLinkInfo>(row).unwrap();

                let link = Link {
                    key: info.key,
                    created_by: info.created_by,
                    created_ago: (now
                        - OffsetDateTime::from_unix_timestamp(info.created_at).unwrap())
                    .try_into()
                    .unwrap(),
                    used_by: info.used_by,
                    used_ago: info.used_at.map(|at| {
                        (now - OffsetDateTime::from_unix_timestamp(at).unwrap())
                            .try_into()
                            .unwrap()
                    }),
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

        audit::log(conn, AuditAction::DeleteInvite(key), &name)?;

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

            let redirect = match create_invite_impl(db, payload.name, services).await {
                Ok(()) => "/admin/invite#added".into(),
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

pub(crate) async fn create_invite_impl(
    db: Connection,
    name: String,
    services: String,
) -> Result<(), Error> {
    db.call(move |conn| {
        let key = create_invite_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        conn.execute(
            "INSERT INTO user_invites (key, created_by, created_at, services)
            VALUES (?1, ?2, ?3, ?4)",
            params![&key, &name, now, services],
        )
        .context("Failed to delete invite")?;

        audit::log(conn, AuditAction::CreateInvite(key), &name)?;

        Ok::<(), anyhow::Error>(())
    })
    .await?;

    Ok(())
}

fn create_invite_key() -> String {
    blob_uuid::random_blob()
}
