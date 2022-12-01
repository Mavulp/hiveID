use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use log::error;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid username or password")]
    InvalidLogin,

    #[error("Passwords do not match")]
    PasswordMismatch,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Failed to refresh auth token: {0}")]
    BadTokenRefresh(String),

    #[error("Unknown service requested: {0}")]
    InvalidService(String),

    #[error("Internal Server Error")]
    InternalError(#[from] anyhow::Error),

    #[error("{0}")]
    JsonRejection(#[from] JsonRejection),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match &self {
            Error::InvalidLogin | Error::InvalidPassword => {
                StatusCode::UNAUTHORIZED
            }
            Error::BadTokenRefresh(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InternalError(e) => {
                let err = e
                    .chain()
                    .skip(1)
                    .fold(e.to_string(), |acc, cause| format!("{}: {}\n", acc, cause));
                error!("API encountered error: {}", err);

                StatusCode::INTERNAL_SERVER_ERROR
            }
            Error::PasswordMismatch
            | Error::JsonRejection(_)
            | Error::InvalidService(_) => StatusCode::BAD_REQUEST,
        };

        let message = if let Error::JsonRejection(rej) = self {
            use std::error::Error;
            match rej {
                JsonRejection::JsonDataError(e) => e.source().unwrap().to_string(),
                JsonRejection::JsonSyntaxError(e) => e.source().unwrap().to_string(),
                _ => rej.to_string(),
            }
        } else {
            self.to_string()
        };

        let body = Json(json!({
            "message": message,
        }));
        (status, body).into_response()
    }
}
