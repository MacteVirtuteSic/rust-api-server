use actix_web::{FromRequest, HttpRequest, dev::Payload, web};
use futures_util::future::{Ready, ready};
use jsonwebtoken::{DecodingKey, Validation, decode};

use crate::AppState;
use crate::errors::AuthError;
use crate::utils::Claims;

impl FromRequest for Claims {
    type Error = AuthError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        // 1. Get the AppState to access the JWT Secret
        let Some(state) = req.app_data::<web::Data<AppState>>() else {
            return ready(Err(AuthError::Internal("Server state missing".into())));
        };

        // 2. Extract Authorization Header
        let auth_header = req.headers().get("Authorization");

        let token = match auth_header {
            Some(h) => h.to_str().unwrap_or("").replace("Bearer ", ""),
            None => return ready(Err(AuthError::Unauthorized)),
        };

        // 3. Decode and Validate
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(state.jwt_secret.as_ref()),
            &Validation::default(),
        );

        match token_data {
            Ok(data) => ready(Ok(data.claims)),
            Err(_) => ready(Err(AuthError::Unauthorized)),
        }
    }
}
