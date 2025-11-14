use crate::response::Response;
use actix_web::{HttpResponse, post, web};
use bcrypt::verify;
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    username: String,
    role: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[post("/auth/login")]
pub async fn login(user: web::Json<LoginRequest>, pool: web::Data<MySqlPool>) -> HttpResponse {
    let user_data = sqlx::query!(
        "SELECT id, name, username, email, password_hash, role FROM users WHERE email = ?",
        user.email
    )
    .fetch_optional(pool.get_ref())
    .await;

    match user_data {
        Ok(Some(db_user)) => {
            let db_password = db_user.password_hash;

            if verify(&user.password, &db_password).unwrap_or(false) {
                let expiration = Utc::now()
                    .checked_add_signed(Duration::days(1))
                    .unwrap()
                    .timestamp() as usize;

                let claims = Claims {
                    sub: db_user.id.to_string(),
                    exp: expiration,
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(
                        std::env::var("JWT_SECRET").unwrap_or_default().as_bytes(),
                    ),
                )
                .unwrap_or_default();

                HttpResponse::Ok().json(Response {
                    message: "Login successful".to_string(),
                    data: Some(LoginResponse {
                        token,
                        username: db_user.username,
                        role: db_user.role,
                        name: db_user.name,
                    }),
                })
            } else {
                HttpResponse::Unauthorized().json(Response {
                    message: "Invalid credentials".to_string(),
                    data: None::<LoginResponse>,
                })
            }
        }
        Ok(None) => HttpResponse::Unauthorized().json(Response {
            message: "Invalid credentials".to_string(),
            data: None::<LoginResponse>,
        }),
        Err(_) => HttpResponse::InternalServerError().json(Response {
            message: "Database error".to_string(),
            data: None::<LoginResponse>,
        }),
    }
}
