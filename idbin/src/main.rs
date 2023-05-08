use argon2::Argon2;
use askama::Template;
use axum::{
    body::{self, boxed, BoxBody, Empty, Full},
    http::{Response, StatusCode},
    routing::{get, get_service, post},
    Extension, Router,
};
use error::Error;
use idlib::{AuthState, IdpClient, SecretKey, Variables};
use log::{info, warn};
use rusqlite_migration::{Migrations, M};
use status::{status_poll_loop, Statuses};
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};

mod accounts;
mod audits;
mod auth;
mod error;
mod home;
mod invites;
mod logging;
mod login;
mod permissions;
mod refresh;
mod register;
mod services;
mod status;
mod token;

pub type Connection = tokio_rusqlite::Connection;

const MIGRATIONS: [M; 2] = [
    M::up(include_str!("../migrations/0001_initial.sql")),
    M::up(include_str!(
        "../migrations/0002_add_service_revoke_url.sql"
    )),
];

pub fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::fmt::Display,
{
    let err = err.to_string();

    warn!("{:?}", err);

    (StatusCode::INTERNAL_SERVER_ERROR, err)
}

#[derive(OpenApi)]
#[openapi(
    paths(
        accounts::get_account_info,
        accounts::update_account_info,
        invites::get_all_invite_infos,
        invites::get_invite_info,
        invites::create_new_invite,
        invites::delete_invite,
        invites::register_with_invite_link,
        services::get_all_services_v2,
        services::update_service_v2,
        services::create_service_v2,
        services::generate_service_secret,
        services::create_new_role_v2,
        services::delete_role_v2,
        audits::get_all_audit_logs,
        auth::login,
        auth::refresh,
    ),
    components(
        schemas(
            accounts::AccountInfo,
            accounts::AccountInfoUpdate,
            accounts::PasswordUpdate,
            invites::InviteInfo,
            invites::CreateInvite,
            invites::RegisterAccount,
            services::ServiceInfo,
            services::UpdateService,
            services::CreateService,
            services::CreateNewRole,
            audits::AuditLog,
            audits::AuditAction,
            audits::UserPermissionChange,
            auth::LoginRequest,
            auth::RefreshRequest,
            auth::RefreshResponse,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "accounts", description = "Account management API"),
        (name = "services", description = "Service management API"),
        (name = "invites", description = "Invite management API"),
        (name = "audits", description = "Audit log management API"),
        (name = "auth", description = "Authentication API"),
    ))]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            )
        }
    }
}

fn v2_api() -> Router {
    Router::new()
        .nest("/accounts", accounts::api_route())
        .nest("/invites", invites::api_route())
        .nest("/services", services::api_route())
        .nest("/audits", audits::api_route())
        .nest("/auth", auth::api_route())
}

#[derive(Clone)]
pub struct PasswordHasher(pub Argon2<'static>);

pub fn api_route(
    db: tokio_rusqlite::Connection,
    secret_key: SecretKey,
    serve_dir: Option<PathBuf>,
    statuses: Statuses,
) -> Router {
    let idp_refresh_address = env::var("IDP_REFRESH_ADDR").unwrap();
    let variables = Variables {
        idp_refresh_address,
        idp_login_address: String::from("/login"),
        token_duration_seconds: 60 * 60,
        service_name: String::from("idbin"),
    };
    let auth_state = AuthState::default();

    let password_hasher = if let Ok(_) = env::var("IDBIN_TEST_HASH") {
        let argon2 = Argon2::new(
            argon2::Algorithm::default(),
            argon2::Version::default(),
            argon2::Params::new(16, 1, 1, None).unwrap(),
        );
        PasswordHasher(argon2)
    } else {
        PasswordHasher(Argon2::default())
    };

    let mut router = Router::new()
        .route("/", get(home::page))
        .route("/login", get(login::page))
        .route("/refresh", post(refresh::post_refresh_token))
        .nest("/register", register::router())
        .nest("/account", accounts::router())
        .nest("/admin/services", services::router())
        .nest("/admin/invite", invites::router())
        .route("/admin/permissions", get(permissions::page))
        .route("/admin/audit", get(audits::page))
        .route("/api/health", get(health))
        .route("/api/login", post(login::post_login))
        .route("/api/permissions", post(permissions::post_permissions))
        .route("/api/account", post(accounts::post_account))
        .nest("/auth", idlib::api_route(None))
        .nest("/api/v2", v2_api())
        .merge(SwaggerUi::new("/api/v2/swagger-ui").url("/api/v2/openapi.json", ApiDoc::openapi()))
        .layer(Extension(IdpClient::default()))
        .layer(Extension(Arc::new(variables)))
        .layer(Extension(db))
        .layer(Extension(secret_key))
        .layer(Extension(auth_state))
        .layer(Extension(statuses))
        .layer(Extension(password_hasher));

    if let Some(serve_dir) = serve_dir {
        router = router.nest_service("/static/", get_service(ServeDir::new(serve_dir)));
    }

    router
}

pub fn into_response<T: Template>(t: &T, _ext: &str) -> Response<BoxBody> {
    match t.render() {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html")
            .body(body::boxed(Full::from(body)))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(body::boxed(Empty::new()))
            .unwrap(),
    }
}

async fn health() -> Result<Response<BoxBody>, Error> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(boxed(Empty::new()))
        .unwrap();

    Ok(response)
}

async fn run() {
    let db_path: PathBuf = env::var("DB_PATH").expect("DB_PATH not set").into();
    let serve_dir: Option<PathBuf> = env::var("SERVE_DIR").ok().map(|p| p.into());
    let secret_key = SecretKey::from_env().unwrap();

    let bind_addr: SocketAddr = env::var("BIND_ADDRESS")
        .expect("BIND_ADDRESS not set")
        .parse()
        .expect("BIND_ADDRESS could not be parsed");

    let conn = tokio_rusqlite::Connection::open(&db_path)
        .await
        .expect("Failed to open database");

    // apply latest migrations
    conn.call(|c| {
        let migrations = Migrations::new(MIGRATIONS.to_vec());
        migrations.to_latest(c).expect("Failed to apply migrations");
    })
    .await;

    let statuses = Statuses(Arc::new(RwLock::new(Vec::new())));

    let router = logging::tracing_layer(api_route(
        conn.clone(),
        secret_key,
        serve_dir,
        statuses.clone(),
    ));

    tokio::spawn(async move {
        status_poll_loop(conn, statuses).await;
    });

    info!("Binding webserver to {bind_addr}");

    axum::Server::try_bind(&bind_addr)
        .expect("Failed to bind server")
        .serve(router.into_make_service())
        .await
        .unwrap();
}

fn main() {
    dotenv::dotenv().ok();
    logging::init();

    info!("Starting hiveID");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { run().await })
}
