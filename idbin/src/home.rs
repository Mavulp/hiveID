use askama::Template;
use axum::{body::BoxBody, http::Response, Extension};
use idlib::AuthorizeCookie;
use reqwest::StatusCode;
use rusqlite::params;

use crate::{error::Error, into_response, status::Statuses, Connection};

pub(crate) struct Service {
    name: String,
    nice_name: String,
    desc: String,
    status: Option<StatusCode>,
}

async fn get_all_services(db: &Connection, Statuses(statuses): Statuses) -> Vec<Service> {
    let statuses = statuses.read().await.clone();

    db.call(move |conn| {
        let mut stmt = conn
            .prepare("SELECT name, nice_name, description FROM services")
            .unwrap();
        let services = stmt
            .query_map(params![], |row| {
                let name: String = row.get(0).unwrap();
                let nice_name: String = row.get(1).unwrap();
                let desc: String = row.get(2).unwrap();
                let status = statuses.iter().find(|s| s.name == name).and_then(|s| s.code);
                Ok(Service { name, nice_name, desc, status })
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        services
    })
    .await
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomePageTemplate<'a> {
    current_page: &'static str,
    admin: bool,
    services: &'a [Service],
}

pub(crate) async fn page(
    AuthorizeCookie(payload, ..): AuthorizeCookie<()>,
    Extension(db): Extension<Connection>,
    Extension(statuses): Extension<Statuses>,
) -> Result<Response<BoxBody>, Error> {
    let services = get_all_services(&db, statuses).await;

    let template = HomePageTemplate {
        current_page: "/",
        admin: payload.groups.iter().any(|g| g == "admin"),
        services: &services,
    };

    Ok(into_response(&template, "html"))
}
