use std::collections::{HashMap, HashSet};

use anyhow::Context;
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Query,
    http::{Response, StatusCode},
    Extension, Form,
};

use futures::{StreamExt};
use idlib::{AuthorizeCookie, IdpClient, SecretKey};


use log::{debug, warn};
use serde::{Deserialize};

use rusqlite::params;
use tokio_rusqlite::Connection;

use crate::{
    audit::{self, UserPermissionChange},
    error::Error,
    into_response,
};

#[derive(Template)]
#[template(path = "permissions.html")]
struct PermissionPageTemplate {
    current_page: &'static str,
    admin: bool,
    service_roles: Vec<ServiceRoles>,
    user_roles: Vec<UserRoles>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct PermissionParams {
    error: Option<String>,
}

async fn get_users(db: &Connection) -> anyhow::Result<Vec<String>> {
    db.call(|conn| {
        let mut stmt = conn
            .prepare("SELECT username FROM users")
            .context("Failed to prepare statement")?;
        let users = stmt
            .query_map(params![], |row| Ok(row.get::<_, String>(0).unwrap()))
            .context("Failed to query users")?
            .collect::<Result<Vec<String>, rusqlite::Error>>()
            .context("Failed to collect users")?;

        Ok(users)
    })
    .await
}

struct ServiceRoles {
    service_name: String,
    roles: Vec<String>,
}

async fn get_all_roles(db: &Connection) -> anyhow::Result<Vec<ServiceRoles>> {
    db.call(|conn| {
        let mut stmt = conn
            .prepare("SELECT service, name FROM roles")
            .context("Failed to prepare statement")?;
        let results = stmt
            .query_map(params![], |row| {
                Ok((row.get(0).unwrap(), row.get(1).unwrap()))
            })
            .context("Failed to query users")?;

        let mut service_roles = HashMap::new();

        for result in results {
            let (service, name) = result.context("Failed to collect roles")?;

            service_roles
                .entry(service)
                .or_insert(Vec::new())
                .push(name);
        }

        let service_roles = service_roles
            .into_iter()
            .map(|(k, v)| ServiceRoles {
                service_name: k,
                roles: v,
            })
            .collect::<Vec<ServiceRoles>>();

        Ok(service_roles)
    })
    .await
}

struct UserRoles {
    user: String,
    roles: HashSet<String>,
}

async fn get_user_roles(db: &Connection) -> anyhow::Result<Vec<UserRoles>> {
    db.call(|conn| {
        let mut stmt = conn
            .prepare(
                "SELECT u.username, ur.role FROM users u \
                LEFT JOIN user_roles ur \
                ON u.username = ur.username",
            )
            .unwrap();
        let results = stmt
            .query_map(params![], |row| {
                Ok((row.get(0).unwrap(), row.get(1).unwrap()))
            })
            .unwrap();

        let mut user_roles = HashMap::new();

        for result in results {
            let (user, role) = result.unwrap();

            let roles = user_roles.entry(user).or_insert(HashSet::new());

            if let Some(role) = role {
                roles.insert(role);
            }
        }

        let user_roles = user_roles
            .into_iter()
            .map(|(k, v)| UserRoles { user: k, roles: v })
            .collect::<Vec<UserRoles>>();

        Ok(user_roles)
    })
    .await
}

pub(crate) async fn page(
    AuthorizeCookie(_): AuthorizeCookie<{ Some("admin") }>,
    Query(params): Query<PermissionParams>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let _users = get_users(&db).await?;
    let service_roles = get_all_roles(&db).await?;
    let user_roles = get_user_roles(&db).await?;

    let template = PermissionPageTemplate {
        current_page: "/admin/permissions",
        admin: true,
        service_roles,
        user_roles,
        error: params.error,
    };

    Ok(into_response(&template, "html"))
}

pub(crate) async fn post_permissions(
    AuthorizeCookie(payload): AuthorizeCookie<{ Some("admin") }>,
    Form(changes): Form<Vec<(String, String)>>,
    Extension(db): Extension<Connection>,
    Extension(client): Extension<IdpClient>,
    Extension(_key): Extension<SecretKey>,
) -> Result<Response<BoxBody>, Error> {
    let redirect = match post_permissions_impl(changes, client, db, payload.name).await {
        Ok(()) => "/admin/permissions#success".into(),
        Err(e) => {
            warn!("Failed to set permissions: {e:?}");

            format!(
                "/admin/permissions?error={}",
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

pub(crate) async fn post_permissions_impl(
    changes: Vec<(String, String)>,
    IdpClient(_client): IdpClient,
    db: Connection,
    performed_by: String,
) -> Result<(), Error> {
    let mut audit_changes = HashMap::new();

    db.call(move |conn| {
        for (id, value) in changes {
            let value = value == "true";

            let mut split = id.split('+');
            let name = split.next().context("Invalid ID")?;
            let service = split.next().context("Invalid ID")?;
            let role = split.next().context("Invalid ID")?;

            debug!("Setting role {service:?}/{role:?} for user {name:?} to {value}");

            let (ref mut added, ref mut removed) = audit_changes
                .entry(name.to_string())
                .or_insert((Vec::new(), Vec::new()));

            if value {
                added.push(format!("{service}/{role}"));

                conn.execute(
                    "INSERT INTO user_roles (username, service, role) \
                    VALUES (?1, ?2, ?3)",
                    params![&name, &service, &role],
                )
                .context("Failed to add permissions")?;
            } else {
                removed.push(format!("{service}/{role}"));

                let rows = conn
                    .execute(
                        "DELETE FROM user_roles \
                    WHERE username = ?1 AND service = ?2 AND role = ?3",
                        params![&name, &service, &role],
                    )
                    .context("Failed to remove permissions")?;

                if rows == 0 {
                    warn!("Tried to delete role but could not find in DB");
                }
            }
        }

        audit::log(
            conn,
            audit::AuditAction::PermissionChange(
                audit_changes
                    .into_iter()
                    .map(|(k, (a, r))| UserPermissionChange {
                        username: k,
                        added: a,
                        removed: r,
                    })
                    .collect::<Vec<_>>(),
            ),
            &performed_by,
        )
    })
    .await?;

    // TODO: update services to invalidate previous token

    /*let services = &*services.values().cloned().collect::<Vec<Service>>();
    let responses = stream::iter(services)
        .map(|service| {
            let permissions = permissions.clone();
            let client = &client;
            let token = &token;
            let auth_url = service.auth_url.clone();

            async move {
                let response = client
                    .put(auth_url)
                    .header("Authorization", format!("Bearer {token}"))
                    .json(&permissions)
                    .send()
                    .await;
                (service.nice_name.clone(), response.ok().map(|r| r.status()))
            }
        })
        .boxed()
        .buffer_unordered(5)
        .collect::<Vec<(String, Option<StatusCode>)>>()
        .await;

    for (service, status) in responses {
        if status.map(|s| s.is_success()).unwrap_or(false) {
            debug!("Updated permissions for {service}");
        } else {
            warn!("Failed to update permissions for {service}: {status:?}");
        }
    }*/

    Ok(())
}
