use std::fmt::Write;

use anyhow::Context;
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Query,
    http::{Response, StatusCode},
    Extension, Form,
};

use casbin::{CoreApi, MgmtApi, RbacApi};
use idlib::Authorizations;

use serde::Deserialize;

use rusqlite::params;
use tokio_rusqlite::Connection;

use crate::{error::Error, into_response};

#[derive(Template)]
#[template(path = "permissions.html")]
struct PermissionPageTemplate {
    all_roles: Vec<String>,
    user_roles: Vec<(String, Vec<bool>)>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct PermissionParams {
    error: Option<String>,
}

async fn get_users(db: &Connection) -> anyhow::Result<Vec<String>> {
    db
        .call(|conn| {
            let mut stmt = conn.prepare("SELECT username FROM users").context("Failed to prepare statement")?;
            let users = stmt
                .query_map(params![], |row| Ok(row.get::<_, String>(0).unwrap()))
                .context("Failed to query users")?
                .collect::<Result<Vec<String>, rusqlite::Error>>()
                .context("Failed to collect users")?;

            Ok(users)
        }).await
}

pub(crate) async fn page(
    Query(params): Query<PermissionParams>,
    Extension(db): Extension<Connection>,
    Extension(Authorizations(auth)): Extension<Authorizations>,
) -> Result<Response<BoxBody>, Error> {
    let mut auth = auth.write().await;

    let users = get_users(&db).await?;
    let all_roles = auth.get_all_roles();
    let user_roles = users
        .iter()
        .map(|u| {
            (u.clone(), {
                let user_roles = auth.get_roles_for_user(&u, None);
                all_roles
                    .iter()
                    .map(|r| user_roles.contains(r))
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();

    let template = PermissionPageTemplate {
        all_roles,
        user_roles,
        error: params.error,
    };

    Ok(into_response(&template, "html"))
}

pub(crate) async fn post_permissions(
    Form(changes): Form<Vec<(String, String)>>,
    Extension(db): Extension<Connection>,
    Extension(auth): Extension<Authorizations>,
) -> Result<Response<BoxBody>, Error> {
    let redirect = match post_permissions_impl(changes, auth, db).await {
        Ok(()) => "/permissions#success".into(),
        Err(e) => format!("/permissions?error={}", urlencoding::encode(&e.to_string())),
    };

    let response = Response::builder()
        .header("Location", &redirect)
        .status(StatusCode::SEE_OTHER)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

pub(crate) async fn post_permissions_impl(
    _changes: Vec<(String, String)>,
    Authorizations(_auth): Authorizations,
    _db: Connection,
) -> Result<(), Error> {
    Ok(())
}
