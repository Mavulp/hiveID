use askama::Template;
use axum::{response::IntoResponse, Extension};
use idlib::AuthorizeCookie;
use reqwest::StatusCode;

use crate::{
    error::Error,
    into_response,
    services::{get_all_services, Service},
    status::Statuses,
    Connection,
};

#[derive(Template)]
#[template(path = "home.html")]
struct HomePageTemplate<'a> {
    current_page: &'static str,
    admin: bool,
    services: &'a [(Service, Option<StatusCode>)],
}

pub(crate) async fn page(
    AuthorizeCookie(payload, maybe_token, ..): AuthorizeCookie<()>,
    Extension(db): Extension<Connection>,
    Extension(statuses): Extension<Statuses>,
) -> impl IntoResponse {
    maybe_token
        .wrap_future(async move {
            let mut services = Vec::new();
            for service in get_all_services(&db).await? {
                let status = statuses
                    .0
                    .read()
                    .await
                    .iter()
                    .find(|s| s.name == service.name)
                    .and_then(|s| s.code);

                services.push((service, status));
            }

            let template = HomePageTemplate {
                current_page: "/",
                admin: payload.groups.iter().any(|g| g == "admin"),
                services: &services,
            };

            Ok::<_, Error>(into_response(&template, "html"))
        })
        .await
}
