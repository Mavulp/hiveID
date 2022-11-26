use std::{fmt::Display, time::Duration};

use anyhow::Context;
use askama::Template;
use axum::{body::BoxBody, http::Response, Extension};
use idlib::AuthorizeCookie;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{error::Error, into_response, Connection};

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

#[derive(Serialize, Deserialize)]
pub enum AuditAction {
    AccountUpdate(bool, bool),
    DeleteInvite(String),
    CreateInvite(String),
    ConsumeInvite(String),
    RegisterUser(String),
    PermissionChange(Vec<UserPermissionChange>),
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
                    write!(f, "<ul>{:?}", change.username)?;

                    for removed in &change.removed {
                        write!(f, "<ul class=\"bad\">{}</ul>", removed)?;
                    }
                    for added in &change.added {
                        write!(f, "<ul class=\"ok\">{}</ul>", added)?;
                    }

                    write!(f, "</ul>")?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserPermissionChange {
    pub username: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

pub struct Action {
    action: AuditAction,
    performed_by: String,
    time_ago: Duration,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditLogPageTemplate<'a> {
    current_page: &'static str,
    admin: bool,
    actions: &'a [Action],
}

mod filters {
    use std::time::Duration;
    use relativetime::NegativeRelativeTime;

    pub fn duration(duration: &Duration) -> ::askama::Result<String> {
        Ok(duration.to_relative_in_past())
    }
}

pub(crate) async fn page(
    AuthorizeCookie(_): AuthorizeCookie<{ Some("admin") }>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let audit_logs = db.call(get_audit_logs).await?;
    let template = AuditLogPageTemplate {
        current_page: "/admin/audit",
        admin: true,
        actions: &audit_logs,
    };

    Ok(into_response(&template, "html"))
}

fn get_audit_logs(conn: &mut rusqlite::Connection) -> anyhow::Result<Vec<Action>> {
    let mut stmt = conn
        .prepare("SELECT action, performed_by, at FROM audit_logs ORDER BY at DESC")
        .context("Failed to prepare statement")?;

    let mut rows = stmt.query(params![])?;

    let now = OffsetDateTime::now_utc();

    let mut audit_logs = Vec::new();
    while let Some(row) = rows.next()? {
        audit_logs.push(Action {
            action: serde_json::de::from_str(row.get_ref(0)?.as_str()?)?,
            performed_by: row.get::<_, String>(1)?,
            time_ago: (now - OffsetDateTime::from_unix_timestamp(row.get(2)?)?).try_into().unwrap(),
        });
    }

    Ok(audit_logs)
}
