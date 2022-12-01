use anyhow::Context;
use askama::Template;
use axum::{
    body::{boxed, BoxBody, Empty},
    extract::{Multipart, Query},
    http::{Response, StatusCode},
    response::IntoResponse,
    Extension, Form,
};

use futures::Future;
use idlib::{AuthorizeCookie, Has, Payload};

use log::{debug, warn};
use serde::Deserialize;

use rusqlite::params;
use serde_rusqlite::from_rows;
use tokio_rusqlite::Connection;

use crate::{
    audit::{self},
    error::Error,
    into_response,
};

fn redirect_result(result: Result<(), Error>, id: Option<&str>) -> impl IntoResponse {
    let id = id.unwrap_or("top");

    let redirect = match result {
        Ok(()) => format!("/admin/services#{id}"),
        Err(e) => {
            warn!("{e:?}");

            format!(
                "/admin/services${id}?error={}",
                urlencoding::encode(&e.to_string())
            )
        }
    };

    Response::builder()
        .header("Location", &redirect)
        .status(StatusCode::SEE_OTHER)
        .body(boxed(Empty::new()))
        .unwrap()
}


#[derive(Template)]
#[template(path = "services.html")]
struct ServicesPageTemplate {
    current_page: &'static str,
    admin: bool,
    services: Vec<Service>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Service {
    name: String,
    nice_name: String,
    description: String,
    icon: Option<String>,
    secret: String,
    callback_url: String,

    #[serde(skip_deserializing)]
    roles: Vec<String>,
}

fn get_roles_for_service(conn: &rusqlite::Connection, name: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(
            "SELECT name \
            FROM roles \
            WHERE service = ?1",
        )
        .unwrap();
    let roles = stmt
        .query_map(params![name], |r| Ok(r.get(0).unwrap()))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    roles
}

async fn get_all_services(db: &Connection) -> anyhow::Result<Vec<Service>> {
    db.call(|conn| {
        let mut stmt = conn
            .prepare(
                "SELECT name, nice_name, description, icon, secret, callback_url \
                FROM services",
            )
            .unwrap();
        let mut services: Vec<Service> = from_rows(stmt.query(params![]).unwrap())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        for service in &mut services {
            service.roles = get_roles_for_service(conn, &service.name);
        }

        Ok(services)
    })
    .await
}

pub(crate) async fn page(
    AuthorizeCookie(..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
) -> Result<Response<BoxBody>, Error> {
    let services = get_all_services(&db).await?;

    let template = ServicesPageTemplate {
        current_page: "/admin/services",
        admin: true,
        services,
        error: None,
    };

    Ok(into_response(&template, "html"))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ServiceUpdate {
    name: String,
    icon: Option<Vec<u8>>,
    display_name: String,
    description: String,
    callback_url: String,
}

async fn parse_service_update(mut multipart: Multipart) -> anyhow::Result<ServiceUpdate> {
    let mut name = None;
    let mut icon = None;
    let mut display_name = None;
    let mut description = None;
    let mut callback_url = None;

    while let Some(field) = multipart.next_field().await.context("Getting next field")? {
        let field_name = field.name().context("Getting field name")?.to_string();
        match field_name.as_str() {
            "name" => name = Some(field.text().await.context("Getting data")?),
            "icon" => icon = Some(field.bytes().await.context("Getting data")?),
            "display-name" => display_name = Some(field.text().await.context("Getting data")?),
            "description" => description = Some(field.text().await.context("Getting data")?),
            "callback-url" => callback_url = Some(field.text().await.context("Getting data")?),
            _ => anyhow::bail!("Unexpected field name {field_name:?} in request"),
        }
    }

    Ok(ServiceUpdate {
        name: name.ok_or_else(|| anyhow::anyhow!("Missing 'name' field."))?,
        icon: icon.map(|b| b.to_vec()),
        display_name: display_name
            .ok_or_else(|| anyhow::anyhow!("Missing 'display-name' field."))?,
        description: description.ok_or_else(|| anyhow::anyhow!("Missing 'description' field."))?,
        callback_url: callback_url
            .ok_or_else(|| anyhow::anyhow!("Missing 'callback-url' field."))?,
    })
}

pub(crate) async fn post_generate_secret(
    AuthorizeCookie(payload, ..): AuthorizeCookie<Has<"admin">>,
    Form(service): Form<NewService>,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    redirect_result(
        generate_secret(db, service.name.clone(), payload).await,
        Some(&service.name),
    )
}

async fn generate_secret(db: Connection, service: String, payload: Payload) -> Result<(), Error> {
    use rand::prelude::*;

    db.call(move |conn| {
        let mut secret_bytes = [0u8; 64];
        StdRng::from_entropy().fill_bytes(&mut secret_bytes[..]);

        let secret = base64::encode(secret_bytes);
        conn.execute(
            "UPDATE services \
            SET secret = ?1 \
            WHERE name = ?2",
            params![secret, &service],
        )
        .context("Failed to update secret for service")?;

        audit::log(
            conn,
            audit::AuditAction::ServiceSecretGenerate(service),
            &payload.name,
        )
        .context("Failed to audit log secret update")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}

async fn transpose_flatten<T, U, E, E2>(result: Result<T, E>) -> Result<U, E2>
where
    T: Future<Output = Result<U, E2>>,
    E2: From<E>,
{
    result?.await
}

pub(crate) async fn post_update_service(
    AuthorizeCookie(payload, ..): AuthorizeCookie<Has<"admin">>,
    multipart: Multipart,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    let result = parse_service_update(multipart).await;
    let id = result.as_ref().map(|update| update.name.clone()).ok();
    let result = result.map(|update| update_service(db, update, payload));

    redirect_result(transpose_flatten(result).await, id.as_deref())
}

pub(crate) async fn update_service(
    db: Connection,
    update: ServiceUpdate,
    payload: Payload,
) -> Result<(), Error> {
    db.call(move |conn| {
        let icon_image = update
            .icon
            .filter(|b| !b.is_empty())
            .map(|b| format!("data:image/png;base64,{}", base64::encode(b)));

        conn.execute(
            "UPDATE services \
            SET nice_name = ?1, description = ?2, callback_url = ?3 \
            WHERE name = ?4",
            params![
                update.display_name,
                update.description,
                update.callback_url,
                &update.name
            ],
        )
        .context("Failed to update service")?;

        if let Some(ref icon) = icon_image {
            conn.execute(
                "UPDATE services \
            SET icon = ?1 \
            WHERE name = ?2",
                params![icon_image, &update.name],
            )
            .context("Failed to update service")?;
        }

        audit::log(
            conn,
            audit::AuditAction::ServiceChange(update.name),
            &payload.name,
        )
        .context("Failed to audit log service update")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct NewService {
    name: String,
}

pub(crate) async fn post_create_service(
    AuthorizeCookie(payload, ..): AuthorizeCookie<Has<"admin">>,
    Form(service): Form<NewService>,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    redirect_result(
        create_new_service(db, service.clone(), payload).await,
        Some(&service.name),
    )
}

async fn create_new_service(
    db: Connection,
    service: NewService,
    payload: Payload,
) -> Result<(), Error> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO services (name, nice_name, description, secret, callback_url) \
            VALUES (?1, ?1, '', '', '')",
            params![&service.name],
        )
        .context("Failed to create new service")?;

        audit::log(
            conn,
            audit::AuditAction::CreatedService(service.name),
            &payload.name,
        )
        .context("Failed to audit log adding role")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Role {
    service_name: String,
    role: String,
}

pub(crate) async fn post_create_new_role(
    AuthorizeCookie(payload, ..): AuthorizeCookie<Has<"admin">>,
    Form(role): Form<Role>,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    redirect_result(
        create_new_role(db, role.clone(), payload).await,
        Some(&role.service_name),
    )
}

async fn create_new_role(db: Connection, role: Role, payload: Payload) -> Result<(), Error> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO roles (name, service) \
            VALUES (?1, ?2)",
            params![&role.role, &role.service_name],
        )
        .context("Failed to create new role")?;

        audit::log(
            conn,
            audit::AuditAction::NewServiceRole(role.service_name, role.role),
            &payload.name,
        )
        .context("Failed to audit log adding role")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}

pub(crate) async fn post_delete_role(
    AuthorizeCookie(payload, ..): AuthorizeCookie<Has<"admin">>,
    Form(role): Form<Role>,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    redirect_result(
        delete_role(db, role.clone(), payload).await,
        Some(&role.service_name),
    )
}

async fn delete_role(db: Connection, role: Role, payload: Payload) -> Result<(), Error> {
    db.call(move |conn| {
        conn.execute(
            "DELETE FROM roles \
            WHERE name = ?1 AND service = ?2",
            params![&role.role, &role.service_name],
        )
        .context("Failed to delete role")?;

        audit::log(
            conn,
            audit::AuditAction::DeletedServiceRole(role.service_name, role.role),
            &payload.name,
        )
        .context("Failed to audit log role deletion")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}
