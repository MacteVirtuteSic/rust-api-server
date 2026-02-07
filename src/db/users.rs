use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use sqlx::PgPool;

use crate::errors::AuthError;
use crate::utils::User;
use crate::utils::UserRegisterRequest;

pub async fn register_user(pool: &PgPool, data: &UserRegisterRequest) -> Result<(), AuthError> {
    // 1. Generate a random salt
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // 2. Hash the password
    let password_hash = argon2
        .hash_password(data.password.as_bytes(), &salt)
        .map_err(|_| AuthError::PasswordHashingError)?
        .to_string(); // This converts the hash + salt + params into a single string

    // 3. Insert into Database
    let result = sqlx::query!(
        "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
        data.username,
        data.email,
        password_hash // Now a safe, PHC-formatted string
    )
    .execute(pool)
    .await;

    // 4. Handle DB Results
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            if let Some(db_err) = e.as_database_error() {
                if db_err.code() == Some("23505".into()) {
                    let constraint = db_err.constraint().unwrap_or("");
                    if constraint.contains("email") {
                        return Err(AuthError::RegisterEmailExists);
                    }
                    if constraint.contains("username") {
                        return Err(AuthError::RegisterUsernameExists);
                    }
                }
            }
            Err(AuthError::DatabaseError(e))
        }
    }
}

pub async fn verify_credentials(
    pool: &sqlx::PgPool,
    email: &str,
    raw_password: &str,
) -> Result<User, AuthError> {
    // 1. Fetch user by email (using CITEXT from earlier makes this case-insensitive)
    let user = sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, superuser, created_at, updated_at
         FROM users WHERE email = $1",
        email
    )
    .fetch_optional(pool)
    .await?
    .ok_or(AuthError::InvalidCredentials)?; // Don't tell them the email was wrong!

    // 2. Verify password hash in Rust
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| AuthError::Internal("Invalid hash format".to_string()))?;

    Argon2::default()
        .verify_password(raw_password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::InvalidCredentials)?;

    Ok(user)
}

// pub async fn update_user() {
//     unimplemented!()
// }
