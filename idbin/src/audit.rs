use std::{fmt::Display, time::Duration};

use anyhow::Context;
use askama::Template;
use axum::{
    response::{IntoResponse, Json},
    routing::get,
    Extension, Router,
};
use hyper::StatusCode;
use idlib::{AuthorizeCookie, Has, Jwt};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::{error::Error, internal_error, into_response, Connection};

pub fn api_route() -> Router {
    Router::new().route("/", get(get_all_audit_logs))
}

type AdminJwt = Jwt<Has<"admin">>;

/// List all audit logs.
#[utoipa::path(
    get,
    path = "/api/v2/audit",
    responses(
        (status = 200, description = "Returns a list of all audit logs", body = [Vec<AuditLog>])
    ),
    security(
        ("api_key" = [])
    )
)]
pub(crate) async fn get_all_audit_logs(
    Jwt(_payload, ..): AdminJwt,
    Extension(db): Extension<Connection>,
) -> Result<Json<Vec<AuditLog>>, (StatusCode, String)> {
    let audit_logs = db.call(get_audit_logs).await.map_err(internal_error)?;

    Ok(Json(audit_logs))
}

pub fn log(conn: &mut rusqlite::Connection, action: AuditAction, user: &str) -> anyhow::Result<()> {
    let now = OffsetDateTime::now_utc();
    let json = serde_json::ser::to_string(&action).context("Failed to serialize audit log")?;
    conn.execute(
        "INSERT INTO audit_logs (action, performed_by, at) VALUES (?1, ?2, ?3)",
        params![json, user, now.unix_timestamp()],
    )
    .context("Failed to insert audit log")?;

    Ok(())
}

#[derive(Serialize, Deserialize, ToSchema)]
pub enum AuditAction {
    AccountUpdate(bool, bool),
    DeleteInvite(String),
    CreateInvite(String),
    ConsumeInvite(String),
    RegisterUser(String),
    PermissionChange(Vec<UserPermissionChange>),
    CreatedService(String),
    ServiceChange(String),
    ServiceSecretGenerate(String),
    NewServiceRole(String, String),
    DeletedServiceRole(String, String),
}

impl Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::DeleteInvite(key) => {
                writeln!(f, "Deleted invite {key:?}")?;
            }
            AuditAction::CreateInvite(key) => {
                writeln!(f, "Created invite {key:?}")?;
            }
            AuditAction::ConsumeInvite(key) => {
                writeln!(f, "Consumed invite {key:?}")?;
            }
            AuditAction::AccountUpdate(password_changed, email_changed) => {
                writeln!(f, "Updated account settings:")?;
                if *password_changed {
                    writeln!(f, "<ul>Password changed</ul>")?;
                }
                if *email_changed {
                    writeln!(f, "<ul>Email changed</ul>")?;
                }
            }
            AuditAction::RegisterUser(username) => write!(f, "Registered user {username:?}")?,
            AuditAction::PermissionChange(changes) => {
                writeln!(f, "Changed user permissions:")?;
                for change in changes {
                    write!(f, "<ul>")?;
                    write!(f, "<li class=\"user\">{}</li>", change.username)?;

                    for removed in &change.removed {
                        write!(f, "<li class=\"bad\">{}</li>", removed)?;
                    }
                    for added in &change.added {
                        write!(f, "<li class=\"ok\">{}</li>", added)?;
                    }

                    write!(f, "</ul>")?;
                }
            }
            AuditAction::CreatedService(service) => {
                writeln!(f, "Created new service {service:?}")?;
            }
            AuditAction::ServiceChange(service) => {
                writeln!(f, "Updated service settings for {service:?}")?;
            }
            AuditAction::ServiceSecretGenerate(service) => {
                writeln!(f, "Regenerated secret for {service:?}")?;
            }
            AuditAction::NewServiceRole(service, role) => {
                writeln!(f, "Added role {role:?} for {service:?}")?;
            }
            AuditAction::DeletedServiceRole(service, role) => {
                writeln!(f, "Deleted role {role:?} for {service:?}")?;
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserPermissionChange {
    pub username: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AuditLog {
    pub action: AuditAction,
    pub performed_by: String,
    pub time_ago: Duration,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditLogPageTemplate<'a> {
    current_page: &'static str,
    admin: bool,
    actions: &'a [AuditLog],
}

mod filters {
    use relativetime::NegativeRelativeTime;
    use std::time::Duration;

    pub fn duration(duration: &Duration) -> ::askama::Result<String> {
        Ok(duration.to_relative_in_past())
    }
}

pub(crate) async fn page(
    AuthorizeCookie(_payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            let audit_logs = db.call(get_audit_logs).await?;
            let template = AuditLogPageTemplate {
                current_page: "/admin/audit",
                admin: true,
                actions: &audit_logs,
            };

            Ok::<_, Error>(into_response(&template, "html"))
        })
        .await
}

fn get_audit_logs(conn: &mut rusqlite::Connection) -> anyhow::Result<Vec<AuditLog>> {
    let mut stmt = conn
        .prepare("SELECT action, performed_by, at FROM audit_logs ORDER BY at DESC")
        .context("Failed to prepare statement")?;

    let mut rows = stmt.query(params![])?;

    let now = OffsetDateTime::now_utc();

    let mut audit_logs = Vec::new();
    while let Some(row) = rows.next()? {
        audit_logs.push(AuditLog {
            action: serde_json::de::from_str(row.get_ref(0)?.as_str()?)?,
            performed_by: row.get::<_, String>(1)?,
            time_ago: (now - OffsetDateTime::from_unix_timestamp(row.get(2)?)?)
                .try_into()
                .unwrap(),
        });
    }

    Ok(audit_logs)
}
