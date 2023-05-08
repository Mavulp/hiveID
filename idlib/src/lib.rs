#![feature(adt_const_params)]
#![allow(incomplete_features)]

use base64::{DecodeError, Engine};
use hmac::{digest::InvalidLength, Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    env::{self},
    num::ParseIntError,
    sync::{atomic::AtomicU64, Arc},
    time::SystemTime,
};
use thiserror::Error;

mod authenticate;
mod authorize;
mod error;

pub use authenticate::*;
pub use authorize::*;
pub use error::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct PermissionResponse {
    pub policy: Vec<Vec<String>>,
    pub group_policy: Vec<Vec<String>>,
}

#[derive(Clone)]
pub struct AuthState {
    last_updated: Arc<AtomicU64>,
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState {
            last_updated: Arc::new(AtomicU64::new(
                SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs(),
            )),
        }
    }
}

#[derive(Clone)]
pub struct SecretKey(pub Arc<Hmac<Sha256>>);

#[derive(Debug, Error)]
pub enum FromEnvError {
    #[error("Environment variable {0} is missing")]
    VarError(&'static str),
    #[error("{0}")]
    ParseError(#[from] ParseIntError),
    #[error("{0}")]
    DecodeError(#[from] DecodeError),
    #[error("{0}")]
    InvalidLengthError(#[from] InvalidLength),
}

impl SecretKey {
    pub fn from_env() -> Result<Self, FromEnvError> {
        let secret_key: String =
            env::var("IDP_SECRET_KEY").map_err(|_| FromEnvError::VarError("IDP_SECRET_KEY"))?;
        let secret_key = base64::engine::general_purpose::STANDARD.decode(&secret_key)?;
        let secret_key = Hmac::<Sha256>::new_from_slice(&secret_key)?;

        Ok(SecretKey(Arc::new(secret_key)))
    }
}

#[derive(Default, Clone)]
pub struct IdpClient(pub reqwest::Client);

pub struct Variables {
    pub idp_refresh_address: String,
    pub idp_login_address: String,
    pub token_duration_seconds: u32,
    pub service_name: String,
}

impl Variables {
    pub fn from_env() -> Result<Self, FromEnvError> {
        Ok(Variables {
            idp_login_address: env::var("IDP_LOGIN_ADDR")
                .map_err(|_| FromEnvError::VarError("IDP_LOGIN_ADDR"))?,
            idp_refresh_address: env::var("IDP_REFRESH_ADDR")
                .map_err(|_| FromEnvError::VarError("IDP_REFRESH_ADDR"))?,
            token_duration_seconds: env::var("TOKEN_DURATION_SECONDS")
                .map_err(|_| FromEnvError::VarError("TOKEN_DURATION_SECONDS"))?
                .parse()?,
            service_name: env::var("SERVICE_NAME")
                .map_err(|_| FromEnvError::VarError("SERVICE_NAME"))?,
        })
    }
}
