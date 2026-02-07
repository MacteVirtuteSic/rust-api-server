use actix_web::{HttpResponse, Responder, post, web};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;

use crate::AppState;
use crate::db::users;
use crate::errors::AuthError;

use crate::utils::{Claims, UserLoginRequest, UserRegisterRequest};

#[post("/register")]
pub async fn register(
    data: web::Json<UserRegisterRequest>,
    state: web::Data<AppState>,
) -> Result<impl Responder, AuthError> {
    users::register_user(&state.db, &data).await?;

    Ok(HttpResponse::Created().json(json!({
        "message": "User registered successfully"
    })))
}

#[post("/login")]
pub async fn login(
    data: web::Json<UserLoginRequest>,
    state: web::Data<AppState>,
) -> Result<impl Responder, AuthError> {
    // 1. Check credentials
    let user = users::verify_credentials(&state.db, &data.email, &data.password).await?;

    // 2. Create JWT Claims
    let role = if user.superuser { "admin" } else { "user" }.to_string();
    let claims = Claims::new(user.id, role);

    // 3. Sign the token
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_ref()), // Store secret in AppState
    )
    .map_err(|_| AuthError::Internal("Token generation failed".into()))?;

    // 4. Return the token
    Ok(HttpResponse::Ok().json(json!({
        "token": token,
        "type": "Bearer"
    })))
}
