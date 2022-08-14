use std::fmt::Write;

use anyhow::Context;
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::Query,
    headers::{authorization::Bearer, Authorization},
    http::{Response, StatusCode},
    Extension, Form, Json, TypedHeader,
};

use casbin::{CoreApi, MgmtApi, RbacApi};
use futures::{stream, StreamExt};
use idlib::{Authorizations, IdpClient, SecretKey};

use jwt::{SignWithKey, VerifyWithKey};
use log::{debug, warn};
use serde::{Deserialize, Serialize};

use rusqlite::params;
use tokio_rusqlite::Connection;

use crate::{error::Error, into_response, Service, Services};

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

pub(crate) async fn page(
    Query(params): Query<PermissionParams>,
    Extension(db): Extension<Connection>,
    Extension(Authorizations(auth)): Extension<Authorizations>,
) -> Result<Response<BoxBody>, Error> {
    let mut auth = auth.write().await;

    let users = get_users(&db).await?;
    let mut all_roles = auth.get_all_roles();
    all_roles.sort_unstable();

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
    Extension(services): Extension<Services>,
    Extension(auth): Extension<Authorizations>,
    Extension(client): Extension<IdpClient>,
    Extension(key): Extension<SecretKey>,
) -> Result<Response<BoxBody>, Error> {
    let redirect = match post_permissions_impl(changes, auth, services, client, key, db).await {
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
    changes: Vec<(String, String)>,
    Authorizations(auth): Authorizations,
    Services(services): Services,
    IdpClient(client): IdpClient,
    key: SecretKey,
    _db: Connection,
) -> Result<(), Error> {
    let mut auth = auth.write().await;

    for (id, value) in changes {
        let value = value == "true";
        let (name, role) = id.split_once('+').context("Invalid ID")?;

        debug!("Setting role {role:?} for user {name:?} to {value}");

        if value {
            auth.add_role_for_user(name, role, None)
                .await
                .context("Failed to add role for user")?;
        } else {
            auth.delete_role_for_user(name, role, None)
                .await
                .context("Failed to remove role for user")?;
        }
    }

    debug!("Saving policy");
    auth.save_policy().await.context("Failed to save policy")?;

    let permissions = PermissionsResponse {
        policy: auth.get_all_policy(),
        group_policy: auth.get_all_grouping_policy(),
    };

    let token = "yup"
        .sign_with_key(&*key.0)
        .context("Failed to sign token")?;

    let services = &*services.values().cloned().collect::<Vec<Service>>();
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
    }

    Ok(())
}

#[derive(Clone, Serialize)]
pub(crate) struct PermissionsResponse {
    policy: Vec<Vec<String>>,
    group_policy: Vec<Vec<String>>,
}

pub(crate) async fn get_permissions(
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Extension(Authorizations(auth)): Extension<Authorizations>,
    Extension(SecretKey(secret_key)): Extension<SecretKey>,
) -> Result<Json<PermissionsResponse>, Error> {
    let claims: String = bearer
        .token()
        .verify_with_key(&*secret_key)
        .context("Failed to verify bearer token")?;
    dbg!(&claims);
    if &claims != "yup" {
        return Err(Error::Unathorized);
    }

    let auth = auth.read().await;

    Ok(Json(PermissionsResponse {
        policy: auth.get_all_policy(),
        group_policy: auth.get_all_grouping_policy(),
    }))
}
