use anyhow::Context;
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use hmac::{Hmac, Mac};
use idlib::{Payload, RefreshTokenRequest, RefreshTokenResponse};
use jwt::VerifyWithKey;
use sha2::Sha256;

use crate::{
    error::Error, login::generate_jwt_for_user_and_service, services::get_service, Connection,
};

#[axum::debug_handler]
pub(crate) async fn post_refresh_token(
    Extension(db): Extension<Connection>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<Response, Error> {
    let token = refresh_token(db, request).await?;

    Ok(Json(RefreshTokenResponse { new_token: token }).into_response())
}

async fn refresh_token(db: Connection, request: RefreshTokenRequest) -> Result<String, Error> {
    let service = get_service(&db, request.service.clone())
        .await?
        .ok_or_else(|| Error::InvalidService(request.service.clone()))?;

    let secret_key = base64::decode(&service.secret).context("Failed to decode service secret")?;
    let secret_key = Hmac::<Sha256>::new_from_slice(&secret_key)
        .context("Failed to create HMAC from secret key")?;

    let payload: Payload = request
        .token
        .verify_with_key(&secret_key)
        .context("Failed to parse JWT")?;

    let token = generate_jwt_for_user_and_service(db, payload.name, &service)
        .await
        .context("Failed to create new JWT token")?;

    Ok(token)
}
