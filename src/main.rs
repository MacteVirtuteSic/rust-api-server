use actix_web::{App, HttpServer, web};
use dotenv::dotenv;
use sqlx::PgPool;

use crate::controllers::{api, auth};

mod controllers;
mod db;
mod errors;
mod middleware;
mod utils;

struct AppState {
    db: PgPool,
    jwt_secret: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("Failed to create pool");

    let state = web::Data::new(AppState {
        db: pool,
        jwt_secret: std::env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(
                web::scope("/auth")
                    .service(auth::register)
                    .service(auth::login),
            )
            .service(
                web::scope("/api").service(api::get_me), // This is now /api/me
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
