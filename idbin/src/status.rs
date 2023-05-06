use std::sync::Arc;

use askama::Template;
use axum::{
    body::BoxBody,
    http::{Response, StatusCode},
    Extension,
};
use reqwest::Client;
use tokio::sync::RwLock;

use crate::Connection;
use crate::{error::Error, into_response};

pub async fn status_poll_loop(_db: Connection, Statuses(_statuses): Statuses) {
    let _client = Client::new();

    /*
    loop {
        let services = services
            .iter()
            .map(|(n, s)| (n.clone(), s.clone()))
            .collect::<Vec<(String, Service)>>();
        let new_statuses = stream::iter(services)
            .map(|(name, service)| {
                let client = &client;
                let url = service.url.clone();
                let health_url = service.health_url.clone();
                async move {
                    let response = client.get(health_url).send().await;
                    Status {
                        nice_name: service.nice_name.clone(),
                        name: name.clone(),
                        url,
                        code: response.ok().map(|r| r.status()),
                    }
                }
            })
            .buffer_unordered(5)
            .collect::<Vec<Status>>()
            .await;

        *statuses.write().await = new_statuses;

        sleep(Duration::from_secs(60)).await;
    }*/
}

#[derive(Clone)]
pub struct Status {
    pub nice_name: String,
    pub name: String,
    pub url: String,
    pub code: Option<StatusCode>,
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.code.map(|c| c.is_success()).unwrap_or(false)
    }
}

#[derive(Clone)]
pub struct Statuses(pub Arc<RwLock<Vec<Status>>>);

#[derive(Template)]
#[template(path = "status.html")]
struct StatusPageTemplate<'a> {
    statuses: &'a [Status],
}

pub(crate) async fn _page(
    Extension(Statuses(statuses)): Extension<Statuses>,
) -> Result<Response<BoxBody>, Error> {
    let statuses = statuses.read().await;

    let template = StatusPageTemplate {
        statuses: &statuses,
    };

    Ok(into_response(&template, "html"))
}
