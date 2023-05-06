use anyhow::Context;
use askama::Template;
use axum::{
    body::{boxed, Empty},
    extract::{Multipart, Path},
    http::{Response, StatusCode},
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
    Extension, Form, Router,
};
use futures::Future;
use idlib::{AuthorizeCookie, Has, Jwt};
use log::warn;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_rusqlite::{from_row, from_rows};
use tokio_rusqlite::Connection;
use utoipa::ToSchema;

use crate::{audit, error::Error, internal_error, into_response};

pub fn api_route() -> Router {
    Router::new()
        .route("/", get(get_all_services_v2))
        .route("/:id", put(update_service_v2))
        .route("/", post(create_service_v2))
        .route("/:id/secret", post(generate_service_secret))
        .route("/:id/roles", post(create_new_role_v2))
        .route("/:id/roles/:role", delete(delete_role_v2))
}

/// Information about a service.
#[derive(Deserialize, Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    /// The ID of the service. This is used in API calls.
    id: String,

    /// The user-facing name of a service.
    nice_name: String,

    /// The description of the service.
    description: String,

    /// The icon in base64 format if one has been set for a service.
    icon: Option<String>,

    /// The secret key used for signing JWTs with a service.
    secret: String,

    /// The callback URL which users will be redirected to after logging in to a service.
    callback_url: String,

    /// A list of roles that can be assigned for a service.
    roles: Vec<String>,
}

/// Update for a service.
#[derive(Deserialize, Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateService {
    /// The user-facing name of a service.
    nice_name: Option<String>,

    /// The description of the service.
    description: Option<String>,

    /// The icon in base64 format if one has been set for a service.
    icon: Option<String>,

    /// The callback URL which users will be redirected to after logging in to a service.
    callback_url: Option<String>,
}

/// Create a new service.
#[derive(Deserialize, Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateService {
    /// The ID of the service.
    id: String,
}

/// Create a new role.
#[derive(Deserialize, Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateNewRole {
    /// The name of the role.
    name: String,
}

type AdminJwt = Jwt<Has<"admin">>;

/// List all services.
#[utoipa::path(
    get,
    path = "/api/v2/service",
    responses(
        (status = 200, description = "List all services successfully", body = [Vec<ServiceInfo>])
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn get_all_services_v2(
    _jwt: AdminJwt,
    Extension(db): Extension<Connection>,
) -> Result<Json<Vec<ServiceInfo>>, (StatusCode, String)> {
    let services = get_all_services(&db)
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(
            |Service {
                 name,
                 nice_name,
                 description,
                 icon,
                 secret,
                 callback_url,
                 roles,
             }| ServiceInfo {
                id: name,
                nice_name,
                description,
                icon,
                secret,
                callback_url,
                roles,
            },
        )
        .collect();

    Ok(Json(services))
}

/// Create a service.
#[utoipa::path(
    post,
    path = "/api/v2/service",
    request_body = CreateService,
    responses(
        (status = 200, description = "Created service successfully")
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn create_service_v2(
    Jwt(payload, ..): AdminJwt,
    Extension(db): Extension<Connection>,
    Json(create): Json<CreateService>,
) -> Result<(), (StatusCode, String)> {
    if create.id.len() == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Cannot create service with empty ID".into(),
        ));
    }

    create_new_service(db, create.id, payload.name)
        .await
        .map_err(internal_error)?;

    Ok(())
}

/// Update a service.
#[utoipa::path(
    put,
    path = "/api/v2/service/{id}",
    request_body = UpdateService,
    params(
        ("id" = String, Path, description = "The service ID")
    ),
    responses(
        (status = 200, description = "Updated service successfully")
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn update_service_v2(
    Jwt(payload, ..): AdminJwt,
    Path(id): Path<String>,
    Extension(db): Extension<Connection>,
    Json(update): Json<UpdateService>,
) -> Result<(), (StatusCode, String)> {
    update_service(db, id, update, payload.name)
        .await
        .map_err(internal_error)?;

    Ok(())
}

/// Regenerate the secret key for a service.
#[utoipa::path(
    post,
    path = "/api/v2/service/{id}/secret",
    params(
        ("id" = String, Path, description = "The service ID")
    ),
    responses(
        (status = 200, description = "Returns the newly regenerated secret key", body=[String])
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn generate_service_secret(
    Jwt(payload, ..): AdminJwt,
    Path(id): Path<String>,
    Extension(db): Extension<Connection>,
) -> Result<String, (StatusCode, String)> {
    let secret = generate_secret(db, id, payload.name)
        .await
        .map_err(internal_error)?;

    Ok(secret)
}

/// Create a new role for a service.
#[utoipa::path(
    post,
    path = "/api/v2/service/{id}/role",
    params(
        ("id" = String, Path, description = "The service ID")
    ),
    request_body = CreateNewRole,
    responses(
        (status = 200, description = "Successfully created a new role for the service.")
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn create_new_role_v2(
    Jwt(payload, ..): AdminJwt,
    Path(id): Path<String>,
    Extension(db): Extension<Connection>,
    Json(new_role): Json<CreateNewRole>,
) -> Result<(), (StatusCode, String)> {
    create_new_role(db, id, new_role.name, payload.name)
        .await
        .map_err(internal_error)?;

    Ok(())
}

/// Delete a role for a service.
#[utoipa::path(
    delete,
    path = "/api/v2/service/{id}/role/{role}",
    params(
        ("id" = String, Path, description = "The service ID"),
        ("role" = String, Path, description = "The role to delete")
    ),
    responses(
        (status = 200, description = "Successfully deleted the role for the service.")
    ),
    security(
        ("api_key" = ["admin"])
    )
)]
pub(crate) async fn delete_role_v2(
    Jwt(payload, ..): AdminJwt,
    Path((id, role)): Path<(String, String)>,
    Extension(db): Extension<Connection>,
) -> Result<(), (StatusCode, String)> {
    delete_role(db, id, role, payload.name)
        .await
        .map_err(internal_error)?;

    Ok(())
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

pub async fn get_all_services(db: &Connection) -> Result<Vec<Service>, Error> {
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

pub async fn get_service(db: &Connection, service_name: String) -> Result<Option<Service>, Error> {
    db.call(move |conn| {
        let service = conn
            .query_row(
                "SELECT name, nice_name, description, icon, secret, callback_url \
                FROM services
                WHERE name=?1",
                params![service_name],
                |row| Ok(from_row::<Service>(row).unwrap()),
            )
            .optional()
            .context("Failed to query service")?;

        Ok(service)
    })
    .await
}

async fn generate_secret(
    db: Connection,
    service_id: String,
    performed_by: String,
) -> Result<String, Error> {
    use rand::prelude::*;

    let secret = db
        .call(move |conn| {
            let mut secret_bytes = [0u8; 64];
            StdRng::from_entropy().fill_bytes(&mut secret_bytes[..]);

            let secret = base64::encode(secret_bytes);
            conn.execute(
                "UPDATE services \
            SET secret = ?1 \
            WHERE name = ?2",
                params![secret, &service_id],
            )
            .context("Failed to update secret for service")?;

            audit::log(
                conn,
                audit::AuditAction::ServiceSecretGenerate(service_id),
                &performed_by,
            )
            .context("Failed to audit log secret update")?;

            Ok::<_, anyhow::Error>(secret)
        })
        .await?;

    Ok(secret)
}

pub(crate) async fn update_service(
    db: Connection,
    service_id: String,
    update: UpdateService,
    performed_by: String,
) -> Result<(), Error> {
    db.call(move |conn| {
        // Update nice name
        if let Some(nice_name) = update.nice_name {
            conn.execute(
                "UPDATE services \
            SET nice_name = ?1 \
            WHERE name = ?2",
                params![nice_name, &service_id],
            )
            .context("Failed to update service")?;
        }

        // Update description
        if let Some(desc) = update.description {
            conn.execute(
                "UPDATE services \
            SET description = ?1 \
            WHERE name = ?2",
                params![desc, &service_id],
            )
            .context("Failed to update service")?;
        }

        // Update URL
        if let Some(url) = update.callback_url {
            conn.execute(
                "UPDATE services \
            SET callback_url = ?1 \
            WHERE name = ?2",
                params![url, &service_id],
            )
            .context("Failed to update service")?;
        }

        // Update icon
        if let Some(ref icon) = update.icon {
            conn.execute(
                "UPDATE services \
            SET icon = ?1 \
            WHERE name = ?2",
                params![icon, &service_id],
            )
            .context("Failed to update service")?;
        }

        audit::log(
            conn,
            audit::AuditAction::ServiceChange(service_id),
            &performed_by,
        )
        .context("Failed to audit log service update")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}

async fn create_new_service(
    db: Connection,
    service_id: String,
    performed_by: String,
) -> Result<(), Error> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO services (name, nice_name, description, secret, callback_url) \
            VALUES (?1, ?1, '', '', '')",
            params![&service_id],
        )
        .context("Failed to create new service")?;

        audit::log(
            conn,
            audit::AuditAction::CreatedService(service_id),
            &performed_by,
        )
        .context("Failed to audit log creating new service")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}

async fn create_new_role(
    db: Connection,
    service_id: String,
    role_name: String,
    performed_by: String,
) -> Result<(), Error> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO roles (name, service) \
            VALUES (?1, ?2)",
            params![&role_name, &service_id],
        )
        .context("Failed to create new role")?;

        audit::log(
            conn,
            audit::AuditAction::NewServiceRole(service_id, role_name),
            &performed_by,
        )
        .context("Failed to audit log adding role")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}

async fn delete_role(
    db: Connection,
    service_id: String,
    role_name: String,
    performed_by: String,
) -> Result<(), Error> {
    db.call(move |conn| {
        conn.execute(
            "DELETE FROM roles \
            WHERE name = ?1 AND service = ?2",
            params![&role_name, &service_id],
        )
        .context("Failed to delete role")?;

        audit::log(
            conn,
            audit::AuditAction::DeletedServiceRole(service_id, role_name),
            &performed_by,
        )
        .context("Failed to audit log role deletion")?;

        Ok::<_, anyhow::Error>(())
    })
    .await?;

    Ok(())
}

// TODO: remove olde stuff belower
//
//

pub fn router() -> Router {
    Router::new()
        .route("/", get(page))
        .route("/", post(post_update_service))
        .route("/create", post(post_create_service))
        .route("/secret/generate", post(post_generate_secret))
        .route("/roles", post(post_create_new_role))
        .route("/roles/delete", post(post_delete_role))
}

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
}

#[derive(Debug, Deserialize)]
pub struct Service {
    pub name: String,
    pub nice_name: String,
    pub description: String,
    pub icon: Option<String>,
    pub secret: String,
    pub callback_url: String,

    #[serde(skip_deserializing)]
    pub roles: Vec<String>,
}

pub(crate) async fn page(
    AuthorizeCookie(_payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            let services = get_all_services(&db).await?;

            let template = ServicesPageTemplate {
                current_page: "/admin/services",
                admin: true,
                services,
            };

            Ok::<_, Error>(into_response(&template, "html"))
        })
        .await
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
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
    Form(service): Form<NewService>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            redirect_result(
                generate_secret(db, service.name.clone(), payload.name)
                    .await
                    .map(|_| ()),
                Some(&service.name),
            )
        })
        .await
}

async fn transpose_flatten<T, U, E, E2>(result: Result<T, E>) -> Result<U, E2>
where
    T: Future<Output = Result<U, E2>>,
    E2: From<E>,
{
    result?.await
}

pub(crate) async fn post_update_service(
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
    multipart: Multipart,
) -> impl IntoResponse {
    let result = parse_service_update(multipart).await;
    let id = result.as_ref().map(|update| update.name.clone()).ok();
    let result = result.map(|update| {
        let id = update.name;
        let update = UpdateService {
            nice_name: Some(update.display_name),
            description: Some(update.description),
            callback_url: Some(update.callback_url),
            icon: update
                .icon
                .filter(|b| !b.is_empty())
                .map(|b| format!("data:image/png;base64,{}", base64::encode(b))),
        };

        update_service(db, id, update, payload.name)
    });

    maybe_token
        .wrap_future(async move { redirect_result(transpose_flatten(result).await, id.as_deref()) })
        .await
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct NewService {
    name: String,
}

pub(crate) async fn post_create_service(
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
    Form(service): Form<NewService>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            redirect_result(
                create_new_service(db, service.name.clone(), payload.name).await,
                Some(&service.name),
            )
        })
        .await
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Role {
    service_name: String,
    role: String,
}

pub(crate) async fn post_create_new_role(
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
    Form(role): Form<Role>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            redirect_result(
                create_new_role(db, role.service_name.clone(), role.role, payload.name).await,
                Some(&role.service_name),
            )
        })
        .await
}

pub(crate) async fn post_delete_role(
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<Has<"admin">>,
    Extension(db): Extension<Connection>,
    Form(role): Form<Role>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            redirect_result(
                delete_role(db, role.service_name.clone(), role.role, payload.name).await,
                Some(&role.service_name),
            )
        })
        .await
}
