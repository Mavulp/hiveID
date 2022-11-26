use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};

use askama::Template;
use axum::{
    body::{self, boxed, BoxBody, Empty, Full},
    http::{Response, StatusCode},
    routing::{get, post, get_service},
    Extension, Router, response::IntoResponse,
};
use error::Error;
use idlib::{IdpClient, SecretKey, Variables};

use rusqlite_migration::{Migrations, M};

use status::{status_poll_loop, Statuses};
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

mod account;
mod audit;
mod error;
mod home;
mod invite;
mod login;
// mod oauth;
mod permissions;
mod register;
mod status;

pub type Connection = tokio_rusqlite::Connection;

const MIGRATIONS: [M; 1] = [M::up(include_str!("../migrations/0001_initial.sql"))];

pub fn api_route(
    db: tokio_rusqlite::Connection,
    secret_key: SecretKey,
    serve_dir: PathBuf,
    statuses: Statuses,
) -> Router {
    let variables = Variables {
        idp_fetch_permission_address: None,
        idp_refresh_address: String::from("/refresh"),
        idp_login_address: String::from("/login"),
        service_name: String::from("idbin"),
    };

    let client = IdpClient::default();

    Router::new()
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
        .route("/api/account", post(account::post_account))
        .nest("/auth", idlib::api_route(client, None))
        .nest(
            "/static/",
            get_service(ServeDir::new(serve_dir)).handle_error(handle_error),
        )
        .layer(Extension(IdpClient::default()))
        .layer(Extension(Arc::new(variables)))
        .layer(Extension(db))
        .layer(Extension(secret_key))
        .layer(Extension(statuses))
}

async fn handle_error(_err: std::io::Error) -> impl IntoResponse {
    (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong...")
}

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
    let _config_file: PathBuf = env::var("CONFIG_FILE").expect("CONFIG_FILE not set").into();
    let db_path: PathBuf = env::var("DB_PATH").expect("DB_PATH not set").into();
    let serve_dir: PathBuf = env::var("SERVE_DIR").expect("SERVE_DIR not set").into();
    let secret_key = SecretKey::from_env();

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
        conn.clone(),
        secret_key,
        serve_dir,
        statuses.clone(),
    );

    tokio::spawn(async move {
        status_poll_loop(conn, statuses).await;
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
