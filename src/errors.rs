use actix_web::{HttpResponse, error::ResponseError, http::StatusCode};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("a user with this email already exists")]
    RegisterEmailExists,

    #[error("this username is already taken")]
    RegisterUsernameExists,

    #[error("database error occurred")]
    DatabaseError(#[from] sqlx::Error),

    #[error("password hashing error")]
    PasswordHashingError,

    #[error("internal server error")]
    Internal(String),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("Unauthorized: missing or invalid token")]
    Unauthorized,
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::RegisterEmailExists | AuthError::RegisterUsernameExists => {
                StatusCode::CONFLICT
            }
            // All of these are "server-side" failures
            AuthError::DatabaseError(_)
            | AuthError::PasswordHashingError
            | AuthError::Internal(_)
            | AuthError::InvalidCredentials => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::Unauthorized => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();

        HttpResponse::build(status).json(json!({
            "error": self.to_string(),
            "code": match self {
                AuthError::RegisterEmailExists => "EMAIL_EXISTS",
                AuthError::RegisterUsernameExists => "USERNAME_EXISTS",
                AuthError::PasswordHashingError => "CRYPTO_ERROR",
                AuthError::DatabaseError(_) => "DATABASE_ERROR",
                AuthError::InvalidCredentials => "INVALID_CREDENTIALS",
                AuthError::Internal(_) => "INTERNAL_SERVER_ERROR",
                AuthError::Unauthorized => "UNAUTHORIZED",
            }
        }))
    }
}
