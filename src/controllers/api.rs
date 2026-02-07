use actix_web::{HttpResponse, Responder, get, web};

use crate::AppState;
use crate::errors::AuthError;
use crate::utils::{Claims, User};

#[get("/me")] // This becomes /auth/me because of the scope
pub async fn get_me(user: Claims, state: web::Data<AppState>) -> Result<impl Responder, AuthError> {
    let user_profile = sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, superuser, created_at, updated_at
         FROM users WHERE id = $1",
        user.sub
    )
    .fetch_one(&state.db)
    .await?;

    Ok(HttpResponse::Ok().json(user_profile))
}
