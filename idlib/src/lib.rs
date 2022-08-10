#![feature(adt_const_params)]

use casbin::Enforcer;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{env, sync::Arc};
use tokio::sync::RwLock;

mod authenticate;
mod authorize;
mod error;

pub use authenticate::*;
pub use authorize::*;
pub use error::*;

#[derive(Clone)]
pub struct SecretKey(pub Arc<Hmac<Sha256>>);

impl SecretKey {
    pub fn from_env() -> Self {
        let secret_key: String = env::var("IDP_SECRET_KEY").expect("IDP_SECRET_KEY not set");
        let secret_key = base64::decode(&secret_key).unwrap();
        let secret_key = Hmac::<Sha256>::new_from_slice(&secret_key)
            .expect("Failed to create HMAC from secret key");

        SecretKey(Arc::new(secret_key))
    }
}

#[derive(Clone)]
pub struct Authorizations(pub Arc<RwLock<Enforcer>>);

#[derive(Default, Clone)]
pub struct IdpClient(pub reqwest::Client);

pub struct Variables {
    pub idp_refresh_address: String,
}

impl Variables {
    pub fn from_env() -> Self {
        Variables {
            idp_refresh_address: env::var("IDP_REFRESH_ADDR").expect("IDP_REFRESH_ADDR not set"),
        }
    }
}
