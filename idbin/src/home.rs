use askama::Template;
use axum::{body::BoxBody, http::Response, Extension};
use casbin::CoreApi;
use idlib::{Authorizations, Authorize};

use crate::{error::Error, into_response, status::Statuses, Service, Services};

#[derive(Template)]
#[template(path = "home.html")]
struct HomePageTemplate<'a> {
    services: &'a [(&'a String, &'a Service, bool)],
}

pub(crate) async fn page(
    Authorize(name): Authorize,
    Extension(Authorizations(auth)): Extension<Authorizations>,
    Extension(Services(services)): Extension<Services>,
    Extension(Statuses(statuses)): Extension<Statuses>,
) -> Result<Response<BoxBody>, Error> {
    let auth = auth.read().await;
    let statuses = statuses.read().await;

    let services = services
        .iter()
        .filter(|(_k, v)| {
            v.show_on_dashboard.unwrap_or(false)
                && v.required_policy
                    .as_ref()
                    .map(|p| auth.enforce((&name, &p, "read")).unwrap_or(false))
                    .unwrap_or(true)
        })
        .map(|(k, v)| {
            (
                k,
                v,
                statuses
                    .iter()
                    .find(|s| &s.name == k)
                    .map(|s| s.is_ok())
                    .unwrap_or(false),
            )
        })
        .collect::<Vec<_>>();
    let template = HomePageTemplate {
        services: &services,
    };

    Ok(into_response(&template, "html"))
}
