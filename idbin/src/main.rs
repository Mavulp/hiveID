use std::{collections::HashMap, env, fs, net::SocketAddr, path::PathBuf, sync::Arc};

use askama::Template;
use axum::{
    body::{self, boxed, BoxBody, Empty, Full},
    http::{Response, StatusCode},
    routing::{get, post},
    Extension, Router,
};
use error::Error;
use idlib::{Authorizations, IdpClient, SecretKey};

use rusqlite_migration::{Migrations, M};
use serde::{Deserialize, Serialize};
use status::{status_poll_loop, Statuses};
use tokio::sync::RwLock;

mod account;
mod audit;
mod error;
mod home;
mod invite;
mod login;
mod permissions;
mod register;
mod status;

pub type Connection = tokio_rusqlite::Connection;

const MIGRATIONS: [M; 1] = [M::up(include_str!("../migrations/0001_initial.sql"))];

pub fn api_route(
    db: tokio_rusqlite::Connection,
    secret_key: SecretKey,
    _serve_dir: PathBuf,
    authorizations: Authorizations,
    services: Services,
    statuses: Statuses,
) -> Router {
    Router::new()
        // .route("/api/streams/:stream", get(stream::get_streams))
        .route("/", get(home::page))
        .route("/login", get(login::page))
        .route("/register", get(register::page))
        .route("/register", post(register::post_page))
        .route("/account", get(account::page))
        .route("/account", post(account::post_page))
        .route("/status", get(status::page))
        .route("/admin/permissions", get(permissions::page))
        .route("/admin/audit", get(audit::page))
        .route("/admin/invite", get(invite::page))
        .route("/admin/invite/create", post(invite::create_page))
        .route("/admin/invite/delete", post(invite::delete_page))
        .route("/api/health", get(health))
        .route("/api/login", post(login::post_login))
        .route("/api/permissions", post(permissions::post_permissions))
        .route("/api/permissions", get(permissions::get_permissions))
        .route("/api/account", post(account::post_account))
        .layer(Extension(IdpClient::default()))
        .layer(Extension(db))
        .layer(Extension(secret_key))
        .layer(Extension(services))
        .layer(Extension(authorizations))
        .layer(Extension(statuses))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceConfig {
    service: HashMap<String, Service>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Service {
    nice_name: String,
    description: Option<String>,
    url: String,
    auth_url: String,
    health_url: String,
    show_on_dashboard: Option<bool>,
    required_policy: Option<String>,
    default_roles: Option<Vec<String>>,
}

impl Service {
    pub fn is_restricted(&self) -> bool {
        self.required_policy.is_some()
    }
}

#[derive(Clone)]
pub struct Services(Arc<HashMap<String, Service>>);

pub fn into_response<T: Template>(t: &T, ext: &str) -> Response<BoxBody> {
    match t.render() {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(
                "content-type",
                askama::mime::extension_to_mime_type(ext).to_string(),
            )
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
    let config_file: PathBuf = env::var("CONFIG_FILE").expect("CONFIG_FILE not set").into();
    let casbin_path: PathBuf = env::var("CASBIN_POLICY")
        .expect("CASBIN_POLICY not set")
        .into();
    let db_path: PathBuf = env::var("DB_PATH").expect("DB_PATH not set").into();
    let serve_dir: PathBuf = env::var("SERVE_DIR").expect("SERVE_DIR not set").into();
    let secret_key = SecretKey::from_env();

    let config = fs::read(config_file).expect("Failed to read config file");
    let services: ServiceConfig = toml::from_slice(&config).expect("Failed to parse config file");
    let services = Services(Arc::new(services.service));

    let authorizations = Authorizations::from_file(casbin_path).await;

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

    let router = api_route(
        conn,
        secret_key,
        serve_dir,
        authorizations,
        services.clone(),
        statuses.clone(),
    );

    tokio::spawn(async move {
        status_poll_loop(statuses, services).await;
    });

    axum::Server::try_bind(&bind_addr)
        .expect("Failed to bind server")
        .serve(router.into_make_service())
        .await
        .unwrap();
}

fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { run().await })
}
