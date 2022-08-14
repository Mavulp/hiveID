#![feature(adt_const_params)]

use casbin::{CoreApi, DefaultModel, Enforcer, FileAdapter, MemoryAdapter, MgmtApi};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{env, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

mod authenticate;
mod authorize;
mod error;

pub use authenticate::*;
pub use authorize::*;
pub use error::*;

#[derive(Serialize, Deserialize)]
pub struct PermissionResponse {
    pub policy: Vec<Vec<String>>,
    pub group_policy: Vec<Vec<String>>,
}

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

async fn get_model() -> DefaultModel {
    DefaultModel::from_str(
        r"
    [request_definition]
    r = sub, obj, act

    [policy_definition]
    p = sub, obj, act

    [role_definition]
    g = _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
            ",
    )
    .await
    .expect("Failed to load model")
}

impl Authorizations {
    pub async fn in_memory() -> Self {
        let model = get_model().await;
        let adapter = MemoryAdapter::default();
        let enforcer = Enforcer::new(model, adapter)
            .await
            .expect("Failed to create enforcer");

        Authorizations(Arc::new(RwLock::new(enforcer)))
    }

    pub async fn from_file(path: PathBuf) -> Self {
        let model = get_model().await;
        let adapter = FileAdapter::new(path);
        let enforcer = Enforcer::new(model, adapter)
            .await
            .expect("Failed to create enforcer");

        Authorizations(Arc::new(RwLock::new(enforcer)))
    }

    pub async fn replace_policy(
        &self,
        policies: Vec<Vec<String>>,
        group_policy: Vec<Vec<String>>,
    ) -> anyhow::Result<()> {
        let mut auth = self.0.write().await;
        auth.clear_policy().await?;

        auth.add_policies(policies).await?;
        auth.add_grouping_policies(group_policy).await?;

        auth.save_policy().await?;

        Ok(())
    }
}

#[derive(Default, Clone)]
pub struct IdpClient(pub reqwest::Client);

pub struct Variables {
    pub idp_fetch_permission_address: Option<String>,
    pub idp_refresh_address: String,
    pub idp_login_address: String,
    pub service_name: String,
}

impl Variables {
    pub fn from_env() -> Self {
        Variables {
            idp_fetch_permission_address: env::var("IDP_FETCH_PERMISSION_ADDR").ok(),
            idp_login_address: env::var("IDP_LOGIN_ADDR").expect("IDP_LOGIN_ADDR not set"),
            idp_refresh_address: env::var("IDP_REFRESH_ADDR").expect("IDP_REFRESH_ADDR not set"),
            service_name: env::var("SERVICE_NAME").expect("SERVICE_NAME not set"),
        }
    }
}
