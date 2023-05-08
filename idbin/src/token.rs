use anyhow::Context;

use base64::Engine;
use hmac::{Hmac, Mac};
use idlib::Payload;
use jwt::SignWithKey;

use sha2::Sha256;

use std::time::SystemTime;

pub fn generate_jwt(
    username: String,
    groups: Vec<String>,
    using_secret: &str,
) -> anyhow::Result<String> {
    let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
    let payload = Payload {
        name: username,
        issued_at: now,
        groups,
    };

    let secret_key = base64::engine::general_purpose::STANDARD
        .decode(&using_secret)
        .context("Failed to decode service secret")?;
    let secret_key = Hmac::<Sha256>::new_from_slice(&secret_key)
        .context("Failed to create HMAC from secret key")?;

    let token = payload
        .sign_with_key(&secret_key)
        .context("Failed to sign payload")?;

    Ok(token)
}
